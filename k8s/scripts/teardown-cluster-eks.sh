#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nemesis}"
AWS_REGION="${AWS_REGION:-us-east-1}"
NAMESPACE="${NAMESPACE:-nemesis}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

KEEP_CLUSTER=false
SKIP_CONFIRM=false
for arg in "$@"; do
    case "$arg" in
        --keep-cluster) KEEP_CLUSTER=true ;;
        --yes|-y) SKIP_CONFIRM=true ;;
        -h|--help)
            echo "Usage: $0 [--keep-cluster] [--yes]"
            echo ""
            echo "Options:"
            echo "  --keep-cluster  Only remove Nemesis and Helm releases, keep EKS cluster running"
            echo "  --yes, -y       Skip confirmation prompt"
            exit 0
            ;;
    esac
done

echo "============================================"
echo "  Nemesis K8s Cluster Teardown (EKS)"
echo "============================================"
echo ""

if [[ "$KEEP_CLUSTER" == "true" ]]; then
    echo "Mode: Removing Helm releases only (--keep-cluster)"
else
    echo "Mode: Full teardown (cluster + IAM resources will be deleted)"
    warn "This will delete the EKS cluster '${CLUSTER_NAME}' in ${AWS_REGION}."
    warn "All data in persistent volumes will be lost."
    echo ""
fi

if [[ "$SKIP_CONFIRM" != "true" ]]; then
    read -rp "Continue? [y/N] " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo ""

# Uninstall Nemesis Helm release
if helm status nemesis -n "$NAMESPACE" &>/dev/null; then
    log "Uninstalling Nemesis Helm release..."
    helm uninstall nemesis -n "$NAMESPACE"
else
    warn "Nemesis Helm release not found"
fi

# Uninstall Traefik
if helm status traefik -n kube-system &>/dev/null; then
    log "Uninstalling Traefik..."
    helm uninstall traefik -n kube-system
else
    warn "Traefik Helm release not found"
fi

# Uninstall Dapr
if helm status dapr -n dapr-system &>/dev/null; then
    log "Uninstalling Dapr..."
    helm uninstall dapr -n dapr-system
else
    warn "Dapr Helm release not found"
fi

# Uninstall KEDA
if helm status keda -n keda &>/dev/null; then
    log "Uninstalling KEDA..."
    helm uninstall keda -n keda
else
    warn "KEDA Helm release not found"
fi

# Uninstall Cluster Autoscaler
if helm status cluster-autoscaler -n kube-system &>/dev/null; then
    log "Uninstalling Cluster Autoscaler..."
    helm uninstall cluster-autoscaler -n kube-system
else
    warn "Cluster Autoscaler Helm release not found"
fi

if [[ "$KEEP_CLUSTER" == "true" ]]; then
    log "Keeping EKS cluster running (--keep-cluster). Only Helm releases were removed."
    log "Teardown complete"
    exit 0
fi

# Clean up EFS resources (filesystem, mount targets, security group, IAM)
log "Cleaning up EFS resources..."
efs_fs_id=$(aws efs describe-file-systems --region "$AWS_REGION" \
    --query "FileSystems[?Tags[?Key=='kubernetes.io/cluster/${CLUSTER_NAME}' && Value=='owned']].FileSystemId" \
    --output text 2>/dev/null || echo "")

if [[ -n "$efs_fs_id" && "$efs_fs_id" != "None" ]]; then
    # Delete mount targets first
    log "Deleting EFS mount targets for ${efs_fs_id}..."
    mount_target_ids=$(aws efs describe-mount-targets \
        --file-system-id "$efs_fs_id" \
        --region "$AWS_REGION" \
        --query 'MountTargets[].MountTargetId' --output text 2>/dev/null || echo "")

    for mt_id in $mount_target_ids; do
        log "  Deleting mount target ${mt_id}..."
        aws efs delete-mount-target --mount-target-id "$mt_id" --region "$AWS_REGION" 2>/dev/null || true
    done

    # Wait for mount targets to be fully deleted
    if [[ -n "$mount_target_ids" ]]; then
        log "Waiting for mount targets to be deleted..."
        mt_retries=0
        while true; do
            mt_count=$(aws efs describe-mount-targets \
                --file-system-id "$efs_fs_id" \
                --region "$AWS_REGION" \
                --query 'length(MountTargets)' --output text 2>/dev/null || echo "0")

            if [[ "$mt_count" == "0" ]]; then
                break
            fi

            if [[ $mt_retries -ge 30 ]]; then
                warn "Mount targets still present after 5 minutes, continuing anyway"
                break
            fi

            sleep 10
            ((mt_retries++))
        done
    fi

    # Delete the EFS filesystem
    log "Deleting EFS filesystem ${efs_fs_id}..."
    aws efs delete-file-system --file-system-id "$efs_fs_id" --region "$AWS_REGION" 2>/dev/null \
        || warn "Could not delete EFS filesystem ${efs_fs_id}"
else
    warn "No EFS filesystem found for cluster ${CLUSTER_NAME}"
fi

# Delete EFS security group
efs_sg_name="efs-${CLUSTER_NAME}"
efs_sg_id=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=${efs_sg_name}" \
    --query 'SecurityGroups[0].GroupId' --output text --region "$AWS_REGION" 2>/dev/null || echo "None")

if [[ "$efs_sg_id" != "None" && -n "$efs_sg_id" ]]; then
    log "Deleting EFS security group ${efs_sg_name} (${efs_sg_id})..."
    aws ec2 delete-security-group --group-id "$efs_sg_id" --region "$AWS_REGION" 2>/dev/null \
        || warn "Could not delete EFS security group (may still have dependencies)"
else
    warn "EFS security group '${efs_sg_name}' not found"
fi

# Delete PVCs before cluster deletion so the EBS CSI driver can clean up the underlying EBS volumes.
# If we skip this, the volumes become orphaned since the CSI controller is gone by the time
# eksctl deletes the cluster.
# Delete PVCs in all Nemesis-related namespaces
for ns in "$NAMESPACE" dapr-system keda; do
    log "Deleting PersistentVolumeClaims in namespace '${ns}'..."
    kubectl delete pvc --all -n "$ns" --timeout=60s 2>/dev/null || warn "No PVCs found in ${ns}"
done
# Give the CSI driver a moment to process the volume deletions
sleep 10

# Delete IAM service accounts
log "Cleaning up IAM service account for EBS CSI driver..."
eksctl delete iamserviceaccount \
    --cluster "$CLUSTER_NAME" \
    --region "$AWS_REGION" \
    --namespace kube-system \
    --name ebs-csi-controller-sa \
    2>/dev/null || warn "EBS CSI IAM service account not found or already deleted"

log "Cleaning up IAM service account for EFS CSI driver..."
eksctl delete iamserviceaccount \
    --cluster "$CLUSTER_NAME" \
    --region "$AWS_REGION" \
    --namespace kube-system \
    --name efs-csi-controller-sa \
    2>/dev/null || warn "EFS CSI IAM service account not found or already deleted"

log "Cleaning up IAM service account for Cluster Autoscaler..."
eksctl delete iamserviceaccount \
    --cluster "$CLUSTER_NAME" \
    --region "$AWS_REGION" \
    --namespace kube-system \
    --name cluster-autoscaler \
    2>/dev/null || warn "Cluster Autoscaler IAM service account not found or already deleted"

# Clean up Cluster Autoscaler IAM policy (must detach from all roles first)
local_account_id=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)
if [[ -n "$local_account_id" ]]; then
    local_policy_arn="arn:aws:iam::${local_account_id}:policy/ClusterAutoscalerPolicy-${CLUSTER_NAME}"
    if aws iam get-policy --policy-arn "$local_policy_arn" &>/dev/null; then
        log "Detaching and deleting Cluster Autoscaler IAM policy..."
        # Detach from all roles before deleting
        for role in $(aws iam list-entities-for-policy --policy-arn "$local_policy_arn" --query 'PolicyRoles[].RoleName' --output text 2>/dev/null); do
            aws iam detach-role-policy --role-name "$role" --policy-arn "$local_policy_arn" 2>/dev/null || true
        done
        aws iam delete-policy --policy-arn "$local_policy_arn" 2>/dev/null || warn "Could not delete autoscaler IAM policy"
    fi
fi

# Delete the EKS cluster
log "Deleting EKS cluster '${CLUSTER_NAME}' in ${AWS_REGION}..."
warn "This will take 10-15 minutes (CloudFormation stack deletion)..."
eksctl delete cluster --name "$CLUSTER_NAME" --region "$AWS_REGION"

echo ""
log "Teardown complete!"
echo ""
echo "Verify no lingering AWS resources:"
echo "  # Check for orphaned EBS volumes"
echo "  aws ec2 describe-volumes --region ${AWS_REGION} \\"
echo "    --filters Name=tag-key,Values=kubernetes.io/cluster/${CLUSTER_NAME} \\"
echo "    --query 'Volumes[].{ID:VolumeId,State:State,Size:Size}' --output table"
echo ""
echo "  # Check for orphaned EFS filesystems"
echo "  aws efs describe-file-systems --region ${AWS_REGION} \\"
echo "    --query \"FileSystems[?Tags[?Key=='kubernetes.io/cluster/${CLUSTER_NAME}']].{ID:FileSystemId,State:LifeCycleState,Name:Name}\" --output table"
echo ""
echo "  # Check for orphaned load balancers"
echo "  aws elbv2 describe-load-balancers --region ${AWS_REGION} \\"
echo "    --query 'LoadBalancers[?contains(LoadBalancerName, \`${CLUSTER_NAME}\`)].{Name:LoadBalancerName,DNS:DNSName}' --output table"
echo ""
echo "  # Check CloudFormation stacks"
echo "  aws cloudformation list-stacks --region ${AWS_REGION} \\"
echo "    --query \"StackSummaries[?contains(StackName, \\\`${CLUSTER_NAME}\\\`) && StackStatus!=\\\`DELETE_COMPLETE\\\`].{Name:StackName,Status:StackStatus}\" --output table"
echo ""
