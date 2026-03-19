# Kubernetes Deployment (EKS)

Deploy Nemesis to [Amazon EKS](https://aws.amazon.com/eks/) (Elastic Kubernetes Service) for production cloud deployments, with the same Dapr operator-managed sidecars and KEDA autoscaling as k3d/k3s.

!!! note
    For local development, use [k3d or k3s](kubernetes.md) instead. EKS is intended for persistent cloud deployments where you need AWS-managed infrastructure, auto-scaling node groups, and internet-accessible endpoints.

!!! warning
    EKS incurs AWS charges (~$244/month minimum). See [Cost Management](#cost-management) and always [tear down](#teardown) when done.

## Why EKS?

| Aspect | k3d | k3s | EKS |
|--------|-----|-----|-----|
| Runtime | k3s inside Docker | Native on host | AWS-managed Kubernetes |
| Infrastructure | Local | VM / bare-metal | AWS cloud |
| Cost | Free | Free | ~$300+/month |
| Storage | Local disk | Local disk | EBS (gp3) + EFS (elastic) |
| Load balancer | Docker port mapping | ServiceLB (Klipper) | AWS NLB |
| Node scaling | Manual | Manual | Managed node groups (auto) |
| Best for | Local dev, CI | VMs, production-like | Cloud production, team use |

**System requirements** are the same as k3d/k3s (4 cores, 12+ GB RAM per node, 100 GB disk).

## Prerequisites

### Tools

| Tool | Install |
|------|---------|
| [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) | See AWS docs |
| [eksctl](https://eksctl.io/installation/) | See Eksctl docs |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | See K8s docs |
| [Helm](https://helm.sh/) | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |

Dapr and KEDA are installed automatically via Helm by the setup script.

### AWS Account Setup

You need an AWS account with an IAM user that has programmatic access.

**1. Create an IAM user (or use an existing one)**

In the [IAM Console](https://console.aws.amazon.com/iam/), create a user with programmatic access. Attach the policy below.

**2. Required IAM permissions**

eksctl needs permissions to create CloudFormation stacks, EC2 instances, EKS clusters, IAM roles, and more. Attach this policy to your IAM user:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:*",
        "ec2:*",
        "elasticfilesystem:*",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:PassRole",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "iam:CreateInstanceProfile",
        "iam:DeleteInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:RemoveRoleFromInstanceProfile",
        "iam:GetInstanceProfile",
        "iam:ListInstanceProfilesForRole",
        "iam:CreateOpenIDConnectProvider",
        "iam:DeleteOpenIDConnectProvider",
        "iam:GetOpenIDConnectProvider",
        "iam:ListOpenIDConnectProviders",
        "iam:TagOpenIDConnectProvider",
        "iam:CreatePolicy",
        "iam:DeletePolicy",
        "iam:GetPolicy",
        "iam:ListEntitiesForPolicy",
        "iam:CreateServiceLinkedRole",
        "iam:TagRole",
        "cloudformation:*",
        "autoscaling:*",
        "elasticloadbalancing:*",
        "ssm:GetParameter",
        "logs:*",
        "sts:GetCallerIdentity",
        "sts:DecodeAuthorizationMessage",
        "kms:CreateKey",
        "kms:CreateAlias",
        "kms:DescribeKey",
        "kms:ListAliases"
      ],
      "Resource": "*"
    }
  ]
}
```

!!! tip
    For a quick start, you can use the AWS-managed `AdministratorAccess` policy instead. The policy above is a more restricted alternative for production use.

**3. Create an Access Key**

In user details, click the "Create access key" button, select "Command Line Interface (CLI)", check the confirmation to continue, add a description and then save the Access key and Secret access key for the next step.

**4. Configure the AWS CLI**

```bash
aws configure
# Enter your Access Key ID, Secret Access Key, and default region (e.g., us-east-1)
```

**5. Verify your credentials**

```bash
aws sts get-caller-identity
```

You should see your account ID, user ARN, and user ID.

## Quick Start

```bash
# 1. Create EKS cluster with EBS CSI, EFS CSI, Traefik, Dapr, KEDA
./k8s/scripts/setup-cluster-eks.sh

# 2. Update values-eks.yaml with the NLB hostname printed by the setup script if you didn't select to regenerate values-eks.yaml
#    (edit nemesis.url to match your NLB hostname)

# 3. Deploy Nemesis
./k8s/scripts/deploy.sh install --values k8s/helm/nemesis/values-eks.yaml

# 4. Verify everything is running
./k8s/scripts/verify.sh
```

Access Nemesis at the NLB hostname printed during setup. The setup script generates random credentials and displays them at the end -- save them!

!!! tip
    Unlike k3d/k3s (which use the default `n`/`n` credentials), the EKS setup script automatically generates a random password with the username `nemesis` to avoid exposing an internet-facing deployment with guessable credentials. The generated htpasswd entry is written to `values-eks.yaml`.

Get the NLB hostname at any time:

```bash
kubectl get svc traefik -n kube-system -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

## Cluster Configuration

### Instance Types

| Instance | vCPUs | RAM | Monthly Cost | Notes |
|----------|-------|-----|-------------|-------|
| `m7i.large` | 2 | 8 GB | ~$74/node | Minimum viable, tight on resources |
| `m7i.xlarge` | 4 | 16 GB | ~$147/node | **Recommended** (default) |
| `m7i.2xlarge` | 8 | 32 GB | ~$294/node | Production with LLM/monitoring stacks |

Costs are approximate on-demand prices for `us-east-1`. The m7i family (Intel Sapphire Rapids, 4th Gen) offers better price-performance and 10x network throughput vs older m5 instances at a similar price point.

### Node Count

The default is 1 node. The Cluster Autoscaler (installed by the setup script) automatically adds nodes when KEDA scales pods beyond what the current nodes can handle.

- **1 node** (`m7i.xlarge`): Default — autoscales up as needed
- **2 nodes** (`m7i.xlarge`): Avoids cold-start delay when scaling
- **3-4 nodes** (`m7i.xlarge`): Production with headroom for burst traffic

### Environment Variable Overrides

All setup script parameters are configurable via environment variables:

```bash
# Example: 3-node cluster with m5.2xlarge in us-west-2
CLUSTER_NAME=nemesis-prod \
AWS_REGION=us-west-2 \
NODE_TYPE=m7i.2xlarge \
NODE_COUNT=3 \
NODE_MIN=3 \
NODE_MAX=6 \
EKS_VERSION=1.31 \
./k8s/scripts/setup-cluster-eks.sh
```

| Variable | Default | Description |
|----------|---------|-------------|
| `CLUSTER_NAME` | `nemesis` | EKS cluster name |
| `AWS_REGION` | `us-east-1` | AWS region |
| `NODE_TYPE` | `m7i.xlarge` | EC2 instance type for nodes |
| `NODE_COUNT` | `1` | Initial node count |
| `NODE_MIN` | `1` | Minimum nodes (auto-scaling) |
| `NODE_MAX` | `4` | Maximum nodes (auto-scaling) |
| `EKS_VERSION` | `1.35` | Kubernetes version |

## Networking and Access

### How It Works

The setup script installs Traefik as a LoadBalancer service with AWS NLB annotations. AWS automatically provisions a Network Load Balancer and assigns it a public hostname.

All Nemesis services are exposed through Traefik IngressRoute CRDs, just like k3d/k3s. The only difference is the entry point: NLB on port 443 instead of localhost:7443.

### Getting the NLB Hostname

```bash
# Get the NLB hostname
kubectl get svc traefik -n kube-system -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

!!! note
    The NLB may take 2-5 minutes to provision after the setup script completes. DNS propagation may add another 1-2 minutes.

### Restricting Access

By default, the NLB is internet-facing. To restrict access to specific IP ranges:

1. Find the NLB in the [EC2 Console > Load Balancers](https://console.aws.amazon.com/ec2/v2/home#LoadBalancers)
2. Go to the NLB's Security tab
3. Edit inbound rules to allow only your IP ranges on ports 443

Alternatively, set the NLB to internal-only:

```bash
# Before running setup, or re-install Traefik with:
helm upgrade traefik traefik/traefik -n kube-system \
  --set "service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-scheme=internal"
```

### Self-Signed TLS (Default)

The setup script generates a self-signed TLS certificate, just like k3d/k3s. Your browser will show a certificate warning, which is expected.

## Optional: ACM + Route53 for Proper TLS

To use a valid TLS certificate with a custom domain:

**1. Set up a Route53 hosted zone** for your domain in the [Route53 Console](https://console.aws.amazon.com/route53/).

**2. Request an ACM certificate** in the [ACM Console](https://console.aws.amazon.com/acm/) for your domain (e.g., `nemesis.example.com`). Use DNS validation and add the CNAME record to Route53.

**3. Create a CNAME record** in Route53 pointing your domain to the NLB hostname:

```
nemesis.example.com → abc123.elb.us-east-1.amazonaws.com
```

**4. Use NLB TLS termination** by adding the ACM certificate ARN to the Traefik service:

```bash
helm upgrade traefik traefik/traefik -n kube-system \
  --set "service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-ssl-cert=arn:aws:acm:us-east-1:123456789012:certificate/abc-123" \
  --set "service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-ssl-ports=443"
```

**5. Update `values-eks.yaml`** with your domain:

```yaml
nemesis:
  url: "https://nemesis.example.com/"
  port: 443
```

Then redeploy: `./k8s/scripts/deploy.sh install --values k8s/helm/nemesis/values-eks.yaml`

## Optional: AWS Managed Services

By default, all infrastructure (PostgreSQL, RabbitMQ, SeaweedFS) runs in-cluster as pods. For production workloads, you can swap these for AWS managed services.

### PostgreSQL to Amazon RDS

Create an RDS PostgreSQL instance and update your Helm values to point at it. You'll need to disable the in-cluster PostgreSQL and update connection settings:

```yaml
# In a custom values file (e.g., values-eks-rds.yaml)
postgres:
  # Disable the in-cluster PostgreSQL deployment
  # (requires adding an `enabled` toggle to the Helm template — not yet supported)
  external:
    host: "your-rds-instance.abc123.us-east-1.rds.amazonaws.com"
    port: "5432"
    database: "enrichment"
```

!!! warning
    The Helm chart does not currently support external database configuration out of the box. You would need to modify the `_helpers.tpl` connection string template and disable the in-cluster PostgreSQL StatefulSet. This is an advanced modification.

### RabbitMQ to Amazon MQ

Amazon MQ supports RabbitMQ as a broker engine. Create an Amazon MQ broker and update the Dapr pub/sub component connection strings in the Helm chart's `dapr/` templates.

!!! warning
    Like RDS, this requires modifying the Helm chart templates to support external connection strings for the Dapr pub/sub components. This is an advanced modification.

### SeaweedFS to Amazon S3

Create an S3 bucket and update the S3 credentials and endpoint in your values file:

```yaml
# In a custom values file
credentials:
  s3:
    accessKey: "YOUR_AWS_ACCESS_KEY"
    secretKey: "YOUR_AWS_SECRET_KEY"
```

You would also need to modify the S3 endpoint environment variables in the Helm templates to point to `s3.amazonaws.com` instead of the in-cluster SeaweedFS service, and disable the in-cluster SeaweedFS deployment.

!!! note
    All three managed service integrations require Helm chart modifications that are not yet abstracted into simple values.yaml toggles. They are documented here for advanced users who want to customize their deployment.

## Storage

### EBS CSI Driver

The setup script automatically installs the [Amazon EBS CSI driver](https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html) and creates a `gp3` StorageClass as the default.

The EKS values overlay (`values-eks.yaml`) uses 10x the base defaults for cloud use:

| Component | Base Default | EKS Default | EBS Cost/month |
|-----------|-------------|-------------|----------------|
| SeaweedFS | 50 Gi | 500 Gi | ~$40 |
| PostgreSQL | 20 Gi | 200 Gi | ~$16 |
| RabbitMQ | 10 Gi | 100 Gi | ~$8 |
| Prometheus | 10 Gi | 100 Gi | ~$8 |
| Loki | 10 Gi | 100 Gi | ~$8 |
| Jaeger | 10 Gi | 100 Gi | ~$8 |
| Grafana | 5 Gi | 50 Gi | ~$4 |
| Phoenix | 5 Gi | 50 Gi | ~$4 |

Adjust sizes in `values-eks.yaml` before deploying if you want smaller (cheaper) or larger volumes.

### gp3 vs gp2

The setup script uses `gp3` volumes, which are newer and cheaper than `gp2`:

- **gp3**: $0.08/GB/month, 3,000 baseline IOPS included
- **gp2**: $0.10/GB/month, IOPS scales with volume size

The script removes the default annotation from `gp2` (if present) so that `gp3` is used for all PVCs.

### EFS CSI Driver (Mounted Containers)

The setup script automatically installs the [Amazon EFS CSI driver](https://docs.aws.amazon.com/eks/latest/userguide/efs-csi.html) and creates an encrypted EFS filesystem for large file processing (disk images, ZIPs, etc.).

**What it does:** Nemesis's `container_monitor` (in the web-api service) watches a `/mounted-containers` directory for large files and processes them. On Docker Compose this is a simple bind mount. On EKS, the setup script provisions an AWS EFS filesystem that:

- Supports `ReadWriteMany` so multiple pods can access it simultaneously
- Can be mounted from outside the cluster (operators copying large files via NFS or a bastion host)
- Is elastic (no pre-provisioned size needed, you only pay for what you store)
- Is encrypted at rest

**This is automatically enabled** when you run `setup-cluster-eks.sh`. The script creates the EFS filesystem, mount targets in each subnet, a security group allowing NFS access from cluster nodes, and writes the configuration to `values-eks.yaml`.

!!! note
    k3d and k3s deployments are unaffected. The `mountedContainers` feature is disabled by default in `values.yaml` and only enabled in the generated `values-eks.yaml`.

#### How to Use

After deploying to EKS, the `/mounted-containers` directory is mounted inside the web-api pod. To copy files for processing:

**Option 1: kubectl cp (simplest)**

```bash
# Copy a file into the mounted-containers volume
kubectl cp /path/to/disk-image.vmdk web-api-<pod-id>:/mounted-containers/ -n nemesis
```

**Option 2: Mount EFS on a bastion host**

Mount the EFS filesystem on an EC2 instance in the same VPC using the NFS protocol:

```bash
# Get the EFS filesystem ID from values-eks.yaml
grep efsFileSystemId k8s/helm/nemesis/values-eks.yaml

# On the bastion host (install amazon-efs-utils first):
sudo mount -t efs <fs-id>:/ /mnt/efs

# Copy files
cp /path/to/disk-image.vmdk /mnt/efs/
```

The `container_monitor` will automatically detect new files and begin processing them.

#### Cleanup Behavior

By default, source files are **deleted** from EFS after successful processing (`cleanupAfterProcessing: true`). This prevents large files from accumulating on the elastic filesystem and driving up EFS costs.

To keep source files for forensic reference or re-processing, set `cleanupAfterProcessing: false` in your values file:

```yaml
mountedContainers:
  enabled: true
  cleanupAfterProcessing: false  # move to completed/ instead of deleting
```

When disabled, processed files are moved to a `completed/` subdirectory within the mounted volume instead of being deleted. You are responsible for manually cleaning up `completed/` to manage EFS storage costs.

#### Verifying EFS is Working

```bash
# Check the PVC is bound
kubectl get pvc mounted-containers -n nemesis

# Check the volume is mounted in web-api
kubectl exec deployment/web-api -n nemesis -- df -h /mounted-containers

# Check container_monitor logs
kubectl logs deployment/web-api -n nemesis | grep -i "container_monitor\|mounted"
```

#### Disabling Mounted Containers

If you don't need large file processing, you can disable it by editing `values-eks.yaml` before deploying:

```yaml
mountedContainers:
  enabled: false
```

Or remove the `mountedContainers` section entirely. When disabled, no PVC is created, no volumeMount is added to web-api, and the container_monitor gracefully skips startup.

#### EFS Costs

EFS pricing is pay-per-use (~$0.30/GB/month for Standard storage class in us-east-1). There is no minimum or pre-provisioned size. An empty filesystem costs nothing. See [EFS Pricing](https://aws.amazon.com/efs/pricing/) for details.

## Cost Management

### Estimated Monthly Costs

| Resource | Cost |
|----------|------|
| EKS control plane | ~$73 |
| 1x m7i.xlarge node (default) | ~$147 |
| EBS storage (80 Gi gp3) | ~$6 |
| EFS (mounted containers) | ~$0 (pay per GB stored) |
| Network Load Balancer | ~$18 base + data |
| **Total (1 node)** | **~$244/month** |

Additional nodes added by the Cluster Autoscaler cost ~$147/month each (m7i.xlarge on-demand).

Costs vary by region. Use the [AWS Pricing Calculator](https://calculator.aws/) for exact estimates.

### Cost Reduction Tips

- **Spot instances**: Add `--spot` to the eksctl node group for up to 70% savings (but nodes can be reclaimed)
- **Smaller instances**: Use `m7i.large` for testing (reduces node cost by ~50%)
- **Single node**: Set `NODE_COUNT=1 NODE_MIN=1` for minimal testing
- **Scheduled scaling**: Scale node group to 0 outside business hours via AWS Console or CLI
- **Reserved instances**: Commit to 1-year or 3-year terms for 30-60% savings on node costs

## Teardown

!!! danger
    Always tear down your EKS cluster when you're done to avoid ongoing AWS charges. A forgotten cluster costs ~$236+/month (more if autoscaled).

```bash
# Full teardown: remove Helm releases, IAM resources, and EKS cluster
./k8s/scripts/teardown-cluster-eks.sh

# Remove only Helm releases, keep the EKS cluster running
./k8s/scripts/teardown-cluster-eks.sh --keep-cluster

# Skip confirmation prompt
./k8s/scripts/teardown-cluster-eks.sh --yes
```

### Verify No Lingering Resources

After teardown, verify no AWS resources remain:

```bash
# Check for orphaned EBS volumes
aws ec2 describe-volumes --region us-east-1 \
  --filters Name=tag-key,Values=kubernetes.io/cluster/nemesis \
  --query 'Volumes[].{ID:VolumeId,State:State,Size:Size}' --output table

# Check for orphaned EFS filesystems
aws efs describe-file-systems --region us-east-1 \
  --query "FileSystems[?Tags[?Key=='kubernetes.io/cluster/nemesis']].{ID:FileSystemId,State:LifeCycleState,Name:Name}" --output table

# Check for orphaned load balancers
aws elbv2 describe-load-balancers --region us-east-1 \
  --query 'LoadBalancers[?contains(LoadBalancerName, `nemesis`)].{Name:LoadBalancerName,DNS:DNSName}' --output table

# Check CloudFormation stacks
aws cloudformation list-stacks --region us-east-1 \
  --query 'StackSummaries[?contains(StackName, `nemesis`) && StackStatus!=`DELETE_COMPLETE`].{Name:StackName,Status:StackStatus}' --output table
```

If you find orphaned EBS volumes, delete them manually:

```bash
aws ec2 delete-volume --volume-id vol-0123456789abcdef0 --region us-east-1
```

## Operations

Operations are the same as k3d/k3s. See the [Kubernetes Deployment](kubernetes.md#operations) guide for details.

### Check Status

```bash
kubectl get pods -n nemesis
kubectl get svc -n nemesis
./k8s/scripts/deploy.sh status
```

### View Logs

```bash
kubectl logs -f deployment/web-api -n nemesis
kubectl logs -f deployment/file-enrichment -n nemesis
kubectl logs -f deployment/file-enrichment -c daprd -n nemesis  # Dapr sidecar
```

### Run Helm Tests

```bash
helm test nemesis -n nemesis
```

## Troubleshooting

### Nodes not joining / NotReady

Check the node group status in the AWS Console (EKS > Clusters > nemesis > Compute). Common causes:

- **IAM permissions**: The node IAM role may be missing permissions. eksctl normally handles this, but verify the role exists.
- **Subnet capacity**: The VPC subnets may not have enough IP addresses. eksctl creates a new VPC by default.

```bash
kubectl get nodes
kubectl describe node <node-name>
```

### Mounted-containers PVC stuck in Pending

The `mounted-containers` PVC uses the EFS CSI driver (not EBS). If it's stuck in Pending:

```bash
# Check if the EFS CSI driver pods are running
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-efs-csi-driver

# Check the EFS CSI driver addon status
aws eks describe-addon --cluster-name nemesis --addon-name aws-efs-csi-driver --region us-east-1

# Check the efs-sc StorageClass exists and has the correct fileSystemId
kubectl get storageclass efs-sc -o yaml

# Verify EFS mount targets are available
aws efs describe-mount-targets --file-system-id <fs-id> --region us-east-1
```

Common causes:

- **EFS CSI driver not installed**: Re-run `setup-cluster-eks.sh` (it's idempotent)
- **Security group misconfigured**: The `efs-<cluster-name>` security group must allow TCP 2049 from the cluster security group
- **Mount targets not ready**: Mount targets take 1-2 minutes to become available after creation

### EBS PVCs stuck in Pending

Almost always caused by a missing or broken EBS CSI driver:

```bash
# Check if the EBS CSI driver pods are running
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-ebs-csi-driver

# Check the EBS CSI driver addon status
aws eks describe-addon --cluster-name nemesis --addon-name aws-ebs-csi-driver --region us-east-1

# Check the gp3 StorageClass exists
kubectl get storageclass
```

If the driver is missing, re-run the setup script (it's idempotent):

```bash
./k8s/scripts/setup-cluster-eks.sh
```

### Image pull errors from ghcr.io

EKS nodes pull images from the internet by default. If pulls fail:

- Verify the nodes have internet access (NAT Gateway in the VPC)
- Check if ghcr.io is accessible: `kubectl run test --image=ghcr.io/specterops/nemesis/web-api:latest --restart=Never`
- For private registries, add `imagePullSecrets` to the namespace

### LoadBalancer stuck in Pending

The Traefik LoadBalancer service creates an AWS NLB. If it stays in Pending:

```bash
kubectl describe svc traefik -n kube-system
```

Common causes:

- **Subnet tags missing**: eksctl normally tags subnets, but verify the public subnets have `kubernetes.io/role/elb=1`
- **IAM permissions**: The cluster needs permissions to create load balancers
- **Quota limits**: Check your NLB quota in the AWS Console (Service Quotas)

### eksctl timeouts (CloudFormation)

Cluster creation takes 15-20 minutes. If it times out:

```bash
# Check CloudFormation stack status
aws cloudformation describe-stacks --region us-east-1 \
  --query 'Stacks[?contains(StackName, `nemesis`)].{Name:StackName,Status:StackStatus}'

# View stack events for error details
aws cloudformation describe-stack-events --region us-east-1 \
  --stack-name eksctl-nemesis-cluster \
  --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`].{Resource:LogicalResourceId,Reason:ResourceStatusReason}'
```

Common causes:

- **Region capacity**: Try a different region or instance type
- **Service quotas**: Check VPC, EIP, and EC2 instance limits in AWS Service Quotas
- **IAM permissions**: Verify your user has the permissions listed in [Prerequisites](#prerequisites)
