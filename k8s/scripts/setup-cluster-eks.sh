#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$K8S_DIR")"

# Configurable via environment variables
CLUSTER_NAME="${CLUSTER_NAME:-nemesis}"
AWS_REGION="${AWS_REGION:-us-east-1}"
NODE_TYPE="${NODE_TYPE:-m7i.xlarge}"
NODE_COUNT="${NODE_COUNT:-1}"
NODE_MIN="${NODE_MIN:-1}"
NODE_MAX="${NODE_MAX:-4}"
EKS_VERSION="${EKS_VERSION:-1.35}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

check_prerequisites() {
    local missing=()

    for cmd in aws eksctl kubectl helm; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing[*]}"
        echo ""
        echo "Install instructions:"
        echo "  aws:     https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        echo "  eksctl:  https://eksctl.io/installation/"
        echo "  kubectl: https://kubernetes.io/docs/tasks/tools/"
        echo "  helm:    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash"
        exit 1
    fi

    log "All prerequisites found"

    # Verify AWS credentials
    log "Verifying AWS credentials..."
    if ! aws sts get-caller-identity &>/dev/null; then
        error "AWS credentials not configured or invalid."
        echo ""
        echo "Run 'aws configure' to set up your credentials, then retry."
        exit 1
    fi

    local account_id
    account_id=$(aws sts get-caller-identity --query Account --output text)
    log "Authenticated to AWS account: ${account_id}"
}

create_cluster() {
    if eksctl get cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" &>/dev/null; then
        warn "EKS cluster '${CLUSTER_NAME}' already exists in ${AWS_REGION}, skipping creation"
        # Ensure kubeconfig is up to date
        aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$AWS_REGION"
        return
    fi

    log "Creating EKS cluster '${CLUSTER_NAME}' in ${AWS_REGION}..."
    log "  Node type:  ${NODE_TYPE}"
    log "  Node count: ${NODE_COUNT} (min: ${NODE_MIN}, max: ${NODE_MAX})"
    log "  EKS version: ${EKS_VERSION}"
    echo ""
    warn "This will take 15-20 minutes (CloudFormation stack creation)..."
    echo ""

    eksctl create cluster \
        --name "$CLUSTER_NAME" \
        --region "$AWS_REGION" \
        --version "$EKS_VERSION" \
        --nodegroup-name "${CLUSTER_NAME}-nodes" \
        --node-type "$NODE_TYPE" \
        --nodes "$NODE_COUNT" \
        --nodes-min "$NODE_MIN" \
        --nodes-max "$NODE_MAX" \
        --with-oidc \
        --managed

    log "EKS cluster created"
}

install_ebs_csi_driver() {
    log "Installing EBS CSI driver..."

    local account_id
    account_id=$(aws sts get-caller-identity --query Account --output text)

    # Check if the IAM role already exists (more reliable than checking the service account)
    local role_name="AmazonEKS_EBS_CSI_DriverRole_${CLUSTER_NAME}"
    if aws iam get-role --role-name "$role_name" &>/dev/null; then
        warn "IAM role '${role_name}' already exists, skipping service account creation"
    else
        log "Creating IAM service account for EBS CSI driver..."
        eksctl create iamserviceaccount \
            --cluster "$CLUSTER_NAME" \
            --region "$AWS_REGION" \
            --namespace kube-system \
            --name ebs-csi-controller-sa \
            --role-name "$role_name" \
            --attach-policy-arn "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy" \
            --approve
    fi

    # Install or update the EBS CSI addon
    if aws eks describe-addon --cluster-name "$CLUSTER_NAME" --addon-name aws-ebs-csi-driver --region "$AWS_REGION" &>/dev/null; then
        warn "EBS CSI driver addon already installed, skipping"
    else
        log "Installing EBS CSI driver addon..."
        local role_arn="arn:aws:iam::${account_id}:role/AmazonEKS_EBS_CSI_DriverRole_${CLUSTER_NAME}"
        aws eks create-addon \
            --cluster-name "$CLUSTER_NAME" \
            --addon-name aws-ebs-csi-driver \
            --region "$AWS_REGION" \
            --service-account-role-arn "$role_arn" \
            --resolve-conflicts OVERWRITE

        log "Waiting for EBS CSI driver to become active (this can take several minutes)..."
        local addon_status=""
        local addon_retries=0
        local addon_max_retries=60  # 60 * 10s = 10 minutes
        while [[ "$addon_status" != "ACTIVE" ]]; do
            addon_status=$(aws eks describe-addon \
                --cluster-name "$CLUSTER_NAME" \
                --addon-name aws-ebs-csi-driver \
                --region "$AWS_REGION" \
                --query 'addon.status' --output text 2>/dev/null || echo "UNKNOWN")

            if [[ "$addon_status" == "ACTIVE" ]]; then
                break
            elif [[ "$addon_status" == "CREATE_FAILED" || "$addon_status" == "DEGRADED" ]]; then
                error "EBS CSI driver addon failed with status: ${addon_status}"
                error "Check: aws eks describe-addon --cluster-name ${CLUSTER_NAME} --addon-name aws-ebs-csi-driver --region ${AWS_REGION}"
                exit 1
            fi

            if [[ $addon_retries -ge $addon_max_retries ]]; then
                error "EBS CSI driver addon did not become active after 10 minutes (status: ${addon_status})"
                exit 1
            fi

            sleep 10
            ((addon_retries++))
        done
    fi

    # Create gp3 StorageClass and set it as default
    if kubectl get storageclass gp3 &>/dev/null; then
        warn "StorageClass 'gp3' already exists, skipping"
    else
        log "Creating gp3 StorageClass..."
        kubectl apply -f - <<'EOF'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: gp3
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: ebs.csi.aws.com
volumeBindingMode: WaitForFirstConsumer
parameters:
  type: gp3
  fsType: ext4
reclaimPolicy: Delete
allowVolumeExpansion: true
EOF
    fi

    # Remove default annotation from gp2 if present
    if kubectl get storageclass gp2 &>/dev/null; then
        kubectl annotate storageclass gp2 storageclass.kubernetes.io/is-default-class- 2>/dev/null || true
    fi

    log "EBS CSI driver installed with gp3 StorageClass"
}

install_efs_csi_driver() {
    log "Installing EFS CSI driver..."

    local account_id
    account_id=$(aws sts get-caller-identity --query Account --output text)

    # Create IAM service account for EFS CSI driver
    local role_name="AmazonEKS_EFS_CSI_DriverRole_${CLUSTER_NAME}"
    if aws iam get-role --role-name "$role_name" &>/dev/null; then
        warn "IAM role '${role_name}' already exists, skipping service account creation"
    else
        log "Creating IAM service account for EFS CSI driver..."
        eksctl create iamserviceaccount \
            --cluster "$CLUSTER_NAME" \
            --region "$AWS_REGION" \
            --namespace kube-system \
            --name efs-csi-controller-sa \
            --role-name "$role_name" \
            --attach-policy-arn "arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy" \
            --approve
    fi

    # Install or update the EFS CSI addon
    if aws eks describe-addon --cluster-name "$CLUSTER_NAME" --addon-name aws-efs-csi-driver --region "$AWS_REGION" &>/dev/null; then
        warn "EFS CSI driver addon already installed, skipping"
    else
        log "Installing EFS CSI driver addon..."
        local role_arn="arn:aws:iam::${account_id}:role/AmazonEKS_EFS_CSI_DriverRole_${CLUSTER_NAME}"
        aws eks create-addon \
            --cluster-name "$CLUSTER_NAME" \
            --addon-name aws-efs-csi-driver \
            --region "$AWS_REGION" \
            --service-account-role-arn "$role_arn" \
            --resolve-conflicts OVERWRITE

        log "Waiting for EFS CSI driver to become active..."
        local addon_status=""
        local addon_retries=0
        local addon_max_retries=60  # 60 * 10s = 10 minutes
        while [[ "$addon_status" != "ACTIVE" ]]; do
            addon_status=$(aws eks describe-addon \
                --cluster-name "$CLUSTER_NAME" \
                --addon-name aws-efs-csi-driver \
                --region "$AWS_REGION" \
                --query 'addon.status' --output text 2>/dev/null || echo "UNKNOWN")

            if [[ "$addon_status" == "ACTIVE" ]]; then
                break
            elif [[ "$addon_status" == "CREATE_FAILED" || "$addon_status" == "DEGRADED" ]]; then
                error "EFS CSI driver addon failed with status: ${addon_status}"
                error "Check: aws eks describe-addon --cluster-name ${CLUSTER_NAME} --addon-name aws-efs-csi-driver --region ${AWS_REGION}"
                exit 1
            fi

            if [[ $addon_retries -ge $addon_max_retries ]]; then
                error "EFS CSI driver addon did not become active after 10 minutes (status: ${addon_status})"
                exit 1
            fi

            sleep 10
            ((addon_retries++))
        done
    fi

    # Discover VPC and subnets from the EKS cluster
    log "Discovering VPC and subnet configuration..."
    local cluster_info
    cluster_info=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" --output json)

    local vpc_id
    vpc_id=$(echo "$cluster_info" | grep -o '"vpcId": "[^"]*"' | head -1 | cut -d'"' -f4)
    log "VPC: ${vpc_id}"

    local cluster_sg
    cluster_sg=$(echo "$cluster_info" | grep -o '"clusterSecurityGroupId": "[^"]*"' | head -1 | cut -d'"' -f4)
    log "Cluster security group: ${cluster_sg}"

    local subnet_ids
    subnet_ids=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" \
        --query 'cluster.resourcesVpcConfig.subnetIds' --output text)

    # Create security group for EFS
    local efs_sg_name="efs-${CLUSTER_NAME}"
    local efs_sg_id=""
    efs_sg_id=$(aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=${efs_sg_name}" "Name=vpc-id,Values=${vpc_id}" \
        --query 'SecurityGroups[0].GroupId' --output text --region "$AWS_REGION" 2>/dev/null || echo "None")

    if [[ "$efs_sg_id" != "None" && -n "$efs_sg_id" ]]; then
        warn "Security group '${efs_sg_name}' already exists: ${efs_sg_id}"
    else
        log "Creating security group '${efs_sg_name}'..."
        efs_sg_id=$(aws ec2 create-security-group \
            --group-name "$efs_sg_name" \
            --description "EFS access for Nemesis EKS cluster ${CLUSTER_NAME}" \
            --vpc-id "$vpc_id" \
            --region "$AWS_REGION" \
            --query 'GroupId' --output text)

        aws ec2 authorize-security-group-ingress \
            --group-id "$efs_sg_id" \
            --protocol tcp \
            --port 2049 \
            --source-group "$cluster_sg" \
            --region "$AWS_REGION"

        aws ec2 create-tags \
            --resources "$efs_sg_id" \
            --tags "Key=kubernetes.io/cluster/${CLUSTER_NAME},Value=owned" "Key=Name,Value=${efs_sg_name}" \
            --region "$AWS_REGION"

        log "Created security group: ${efs_sg_id}"
    fi

    # Create EFS filesystem
    local existing_efs
    existing_efs=$(aws efs describe-file-systems --region "$AWS_REGION" \
        --query "FileSystems[?Tags[?Key=='kubernetes.io/cluster/${CLUSTER_NAME}' && Value=='owned']].FileSystemId" \
        --output text 2>/dev/null || echo "")

    if [[ -n "$existing_efs" && "$existing_efs" != "None" ]]; then
        warn "EFS filesystem already exists: ${existing_efs}"
        EFS_FILE_SYSTEM_ID="$existing_efs"
    else
        log "Creating EFS filesystem..."
        EFS_FILE_SYSTEM_ID=$(aws efs create-file-system \
            --encrypted \
            --performance-mode generalPurpose \
            --throughput-mode bursting \
            --tags "Key=Name,Value=nemesis-${CLUSTER_NAME}" "Key=kubernetes.io/cluster/${CLUSTER_NAME},Value=owned" \
            --region "$AWS_REGION" \
            --query 'FileSystemId' --output text)

        log "Created EFS filesystem: ${EFS_FILE_SYSTEM_ID}"

        # Wait for filesystem to become available
        log "Waiting for EFS filesystem to become available..."
        local efs_status=""
        local efs_retries=0
        while [[ "$efs_status" != "available" ]]; do
            efs_status=$(aws efs describe-file-systems \
                --file-system-id "$EFS_FILE_SYSTEM_ID" \
                --region "$AWS_REGION" \
                --query 'FileSystems[0].LifeCycleState' --output text 2>/dev/null || echo "unknown")

            if [[ "$efs_status" == "available" ]]; then
                break
            fi

            if [[ $efs_retries -ge 30 ]]; then
                error "EFS filesystem did not become available after 5 minutes"
                exit 1
            fi

            sleep 10
            ((efs_retries++))
        done
    fi

    # Create mount targets (one per subnet)
    log "Creating EFS mount targets..."
    for subnet_id in $subnet_ids; do
        if aws efs create-mount-target \
            --file-system-id "$EFS_FILE_SYSTEM_ID" \
            --subnet-id "$subnet_id" \
            --security-groups "$efs_sg_id" \
            --region "$AWS_REGION" &>/dev/null; then
            log "  Created mount target in subnet ${subnet_id}"
        else
            warn "  Mount target in subnet ${subnet_id} already exists or AZ conflict (OK)"
        fi
    done

    # Wait for mount targets to become available
    log "Waiting for mount targets to become available..."
    local mt_retries=0
    while true; do
        local mt_states
        mt_states=$(aws efs describe-mount-targets \
            --file-system-id "$EFS_FILE_SYSTEM_ID" \
            --region "$AWS_REGION" \
            --query 'MountTargets[].LifeCycleState' --output text 2>/dev/null || echo "")

        if [[ -n "$mt_states" ]] && ! echo "$mt_states" | grep -q "creating"; then
            break
        fi

        if [[ $mt_retries -ge 30 ]]; then
            warn "Some mount targets still not available after 5 minutes, continuing anyway"
            break
        fi

        sleep 10
        ((mt_retries++))
    done

    log "EFS CSI driver installed with filesystem ${EFS_FILE_SYSTEM_ID}"
}

install_traefik() {
    log "Installing Traefik via Helm..."
    helm repo add traefik https://traefik.github.io/charts 2>/dev/null || true
    helm repo update traefik

    if helm status traefik -n kube-system &>/dev/null; then
        warn "Traefik already installed, skipping"
        return
    fi

    helm install traefik traefik/traefik \
        --namespace kube-system \
        --version 34.3.0 \
        --set "service.type=LoadBalancer" \
        --set "service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-type=nlb" \
        --set "service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-scheme=internet-facing" \
        --set "ports.websecure.expose.default=true" \
        --set "ports.websecure.exposedPort=443" \
        --set "ports.web.expose.default=false" \
        --set "ingressRoute.dashboard.enabled=false" \
        --set "providers.kubernetesIngress.enabled=true" \
        --set "providers.kubernetesCRD.enabled=true" \
        --set "providers.kubernetesCRD.allowCrossNamespace=true" \
        --wait

    log "Traefik installed"
}

install_dapr() {
    log "Installing Dapr via Helm..."
    helm repo add dapr https://dapr.github.io/helm-charts/ 2>/dev/null || true
    helm repo update dapr

    if helm status dapr -n dapr-system &>/dev/null; then
        warn "Dapr already installed, skipping"
        return
    fi

    helm install dapr dapr/dapr \
        --namespace dapr-system \
        --create-namespace \
        --version 1.16.9 \
        --set global.logAsJson=true \
        --wait --timeout 5m

    log "Dapr installed"
    kubectl get pods -n dapr-system
}

install_keda() {
    log "Installing KEDA via Helm..."
    helm repo add kedacore https://kedacore.github.io/charts 2>/dev/null || true
    helm repo update kedacore

    if helm status keda -n keda &>/dev/null; then
        warn "KEDA already installed, skipping"
        return
    fi

    helm install keda kedacore/keda \
        --namespace keda \
        --create-namespace \
        --version 2.16.1 \
        --wait

    log "KEDA installed"
}

install_cluster_autoscaler() {
    log "Installing Cluster Autoscaler..."

    if helm status cluster-autoscaler -n kube-system &>/dev/null; then
        warn "Cluster Autoscaler already installed, skipping"
        return
    fi

    # Create IAM policy for the autoscaler
    local account_id
    account_id=$(aws sts get-caller-identity --query Account --output text)
    local policy_name="ClusterAutoscalerPolicy-${CLUSTER_NAME}"
    local policy_arn="arn:aws:iam::${account_id}:policy/${policy_name}"

    if aws iam get-policy --policy-arn "$policy_arn" &>/dev/null; then
        warn "IAM policy '${policy_name}' already exists, skipping"
    else
        log "Creating IAM policy for Cluster Autoscaler..."
        aws iam create-policy \
            --policy-name "$policy_name" \
            --policy-document '{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "autoscaling:DescribeAutoScalingGroups",
                            "autoscaling:DescribeAutoScalingInstances",
                            "autoscaling:DescribeLaunchConfigurations",
                            "autoscaling:DescribeScalingActivities",
                            "autoscaling:DescribeTags",
                            "autoscaling:SetDesiredCapacity",
                            "autoscaling:TerminateInstanceInAutoScalingGroup",
                            "ec2:DescribeImages",
                            "ec2:DescribeInstanceTypes",
                            "ec2:DescribeLaunchTemplateVersions",
                            "ec2:GetInstanceTypesFromInstanceRequirements",
                            "eks:DescribeNodegroup"
                        ],
                        "Resource": "*"
                    }
                ]
            }' > /dev/null
    fi

    # Create IAM service account for the autoscaler
    local role_name="ClusterAutoscalerRole-${CLUSTER_NAME}"
    if ! aws iam get-role --role-name "$role_name" &>/dev/null; then
        log "Creating IAM service account for Cluster Autoscaler..."
        eksctl create iamserviceaccount \
            --cluster "$CLUSTER_NAME" \
            --region "$AWS_REGION" \
            --namespace kube-system \
            --name cluster-autoscaler \
            --role-name "$role_name" \
            --attach-policy-arn "$policy_arn" \
            --approve
    else
        warn "IAM role '${role_name}' already exists, skipping service account creation"
    fi

    helm repo add autoscaler https://kubernetes.github.io/autoscaler 2>/dev/null || true
    helm repo update autoscaler

    helm install cluster-autoscaler autoscaler/cluster-autoscaler \
        --namespace kube-system \
        --set "autoDiscovery.clusterName=${CLUSTER_NAME}" \
        --set "awsRegion=${AWS_REGION}" \
        --set "rbac.serviceAccount.create=false" \
        --set "rbac.serviceAccount.name=cluster-autoscaler" \
        --set "extraArgs.balance-similar-node-groups=true" \
        --set "extraArgs.skip-nodes-with-system-pods=false" \
        --set "extraArgs.scale-down-delay-after-add=5m" \
        --set "extraArgs.scale-down-unneeded-time=5m" \
        --wait

    log "Cluster Autoscaler installed"
}

create_namespace() {
    if kubectl get namespace nemesis &>/dev/null; then
        warn "Namespace nemesis already exists, skipping"
    else
        log "Creating nemesis namespace"
        kubectl create namespace nemesis
    fi
    kubectl label namespace nemesis dapr.io/inject=true --overwrite
}

create_tls_secret() {
    if kubectl get secret nemesis-tls-secret -n nemesis &>/dev/null; then
        warn "TLS secret already exists, skipping"
        return
    fi

    # Try to use existing certs from the repo
    local cert_dir="${REPO_ROOT}/infra/traefik/certs"
    if [[ -f "$cert_dir/cert.pem" && -f "$cert_dir/key.pem" ]]; then
        log "Creating TLS secret from existing certs in infra/traefik/certs/"
        kubectl create secret tls nemesis-tls-secret \
            --namespace nemesis \
            --cert="$cert_dir/cert.pem" \
            --key="$cert_dir/key.pem"
        return
    fi

    # Try to get NLB hostname for the SAN
    local nlb_hostname=""
    nlb_hostname=$(kubectl get svc traefik -n kube-system -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)

    local san="DNS:localhost,IP:127.0.0.1"
    if [[ -n "$nlb_hostname" ]]; then
        san="DNS:localhost,DNS:${nlb_hostname},IP:127.0.0.1"
        log "Including NLB hostname in TLS SAN: ${nlb_hostname}"
    else
        warn "NLB hostname not available yet, generating cert with localhost SAN only"
        warn "You can regenerate the cert later once the NLB is ready"
    fi

    # Generate self-signed certs
    log "Generating self-signed TLS certificate..."
    local tmp_dir
    tmp_dir=$(mktemp -d)
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
        -keyout "$tmp_dir/tls.key" -out "$tmp_dir/tls.crt" \
        -subj "/CN=nemesis" \
        -addext "subjectAltName=${san}" \
        2>/dev/null

    kubectl create secret tls nemesis-tls-secret \
        --namespace nemesis \
        --cert="$tmp_dir/tls.crt" \
        --key="$tmp_dir/tls.key"

    rm -rf "$tmp_dir"
    log "TLS secret created with self-signed cert"
}

configure_values_file() {
    local values_file="${K8S_DIR}/helm/nemesis/values-eks.yaml"

    # --- Resolve NLB hostname ---
    log "Retrieving NLB hostname..."
    NLB_HOSTNAME=""
    local retries=0
    while [[ -z "$NLB_HOSTNAME" ]] && [[ $retries -lt 60 ]]; do
        NLB_HOSTNAME=$(kubectl get svc traefik -n kube-system -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)
        if [[ -z "$NLB_HOSTNAME" ]]; then
            sleep 5
            ((retries++))
        fi
    done

    if [[ -n "$NLB_HOSTNAME" ]]; then
        log "NLB Hostname: ${NLB_HOSTNAME}"
    else
        warn "NLB hostname not available yet. You will need to update values-eks.yaml manually later."
        warn "  kubectl get svc traefik -n kube-system -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'"
    fi

    # --- Generate credentials ---
    GENERATED_USER="nemesis"
    GENERATED_PASSWORD=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 16)
    local htpasswd_hash
    htpasswd_hash=$(openssl passwd -apr1 "$GENERATED_PASSWORD")
    GENERATED_BASIC_AUTH="${GENERATED_USER}:${htpasswd_hash}"
    log "Generated random basic auth credentials"

    # --- Show summary and prompt ---
    echo ""
    echo "============================================"
    echo "  values-eks.yaml Configuration"
    echo "============================================"
    echo ""
    if [[ -n "$NLB_HOSTNAME" ]]; then
        echo "  NLB URL:  https://${NLB_HOSTNAME}/"
    else
        echo "  NLB URL:  (not yet available)"
    fi
    echo "  Username: ${GENERATED_USER}"
    echo "  Password: ${GENERATED_PASSWORD}"
    echo ""

    if [[ -f "$values_file" ]]; then
        warn "This will overwrite: ${values_file}"
    fi

    read -rp "Write these settings to values-eks.yaml? [Y/n] " confirm
    if [[ "$confirm" == "n" || "$confirm" == "N" ]]; then
        warn "Skipping values-eks.yaml write."
        warn "You will need to manually set the NLB hostname and credentials in values-eks.yaml."
        return
    fi

    # --- Write the file ---
    local nemesis_url="https://REPLACE_WITH_NLB_HOSTNAME/"
    if [[ -n "$NLB_HOSTNAME" ]]; then
        nemesis_url="https://${NLB_HOSTNAME}/"
    fi

    cat > "$values_file" <<EOF
# EKS overrides — use with: ./k8s/scripts/deploy.sh install --values k8s/helm/nemesis/values-eks.yaml
# Generated by setup-cluster-eks.sh on $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# All infrastructure (PostgreSQL, RabbitMQ, SeaweedFS) runs in-cluster by default.

nemesis:
  url: "${nemesis_url}"
  port: 443

# EBS gp3 storage (created by setup-cluster-eks.sh).
# Sizes below are 10x the base defaults for cloud use. Adjust before deploying
# if you want smaller (cheaper) or larger volumes. EBS gp3 costs ~\$0.08/GB/month.
# Volumes can be expanded later without downtime (gp3 has allowVolumeExpansion: true).
postgres:
  storage:
    size: 200Gi
    storageClass: gp3

rabbitmq:
  storage:
    size: 100Gi
    storageClass: gp3

seaweedfs:
  storage:
    size: 500Gi
    storageClass: gp3

monitoring:
  prometheus:
    storage:
      size: 100Gi
      storageClass: gp3
  grafana:
    storage:
      size: 50Gi
      storageClass: gp3
  loki:
    storage:
      size: 100Gi
      storageClass: gp3
  jaeger:
    storage:
      size: 100Gi
      storageClass: gp3

llm:
  phoenix:
    storage:
      size: 50Gi
      storageClass: gp3

# Generated credentials (do not use defaults for internet-facing deployments)
credentials:
  basicAuthUsers: "${GENERATED_BASIC_AUTH}"

# Mounted containers (EFS-backed shared filesystem for large file processing)
mountedContainers:
  enabled: true
  storage:
    size: 100Gi
    storageClass: efs-sc
    efsFileSystemId: "${EFS_FILE_SYSTEM_ID}"
EOF

    log "Wrote ${values_file}"
}

main() {
    echo "============================================"
    echo "  Nemesis K8s Cluster Setup (EKS)"
    echo "============================================"
    echo ""

    check_prerequisites
    create_cluster
    install_ebs_csi_driver
    install_efs_csi_driver
    install_traefik
    install_dapr
    install_keda
    install_cluster_autoscaler
    create_namespace
    create_tls_secret
    configure_values_file

    echo ""
    log "Setup complete!"
    echo ""
    echo "============================================"
    echo "  Credentials (save these!)"
    echo "============================================"
    echo "  Username: ${GENERATED_USER}"
    echo "  Password: ${GENERATED_PASSWORD}"
    if [[ -n "${NLB_HOSTNAME:-}" ]]; then
        echo "  URL:      https://${NLB_HOSTNAME}"
    fi
    echo ""
    echo "Next steps:"
    echo "  1. Deploy Nemesis:"
    echo "     ./k8s/scripts/deploy.sh install --values k8s/helm/nemesis/values-eks.yaml"
    echo "  2. Verify deployment:"
    echo "     ./k8s/scripts/verify.sh"
    echo ""
    echo "Cluster info:"
    echo "  Runtime:  EKS ${EKS_VERSION}"
    echo "  Region:   ${AWS_REGION}"
    echo "  Nodes:    ${NODE_COUNT} x ${NODE_TYPE}"
    echo ""
    echo "To tear down (avoid surprise AWS charges!):"
    echo "  ./k8s/scripts/teardown-cluster-eks.sh"
    echo ""
}

main "$@"
