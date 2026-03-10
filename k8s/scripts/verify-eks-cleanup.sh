#!/usr/bin/env bash
set -euo pipefail

# Verifies that all AWS resources provisioned by setup-cluster-eks.sh have been
# cleaned up. Run this after teardown-cluster-eks.sh to confirm nothing is
# lingering in your account.

CLUSTER_NAME="${CLUSTER_NAME:-nemesis}"
AWS_REGION="${AWS_REGION:-us-east-1}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "  ${GREEN}PASS${NC} $*"; ((PASS++)) || true; }
fail() { echo -e "  ${RED}FAIL${NC} $*"; ((FAIL++)) || true; }

echo "============================================"
echo "  Nemesis EKS Cleanup Verification"
echo "  Cluster: ${CLUSTER_NAME}"
echo "  Region:  ${AWS_REGION}"
echo "============================================"
echo ""

# --- EKS Cluster ---
echo "=== EKS Cluster ==="
if eksctl get cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" &>/dev/null; then
    fail "EKS cluster '${CLUSTER_NAME}' still exists"
else
    pass "EKS cluster '${CLUSTER_NAME}' not found"
fi
echo ""

# --- CloudFormation Stacks ---
echo "=== CloudFormation Stacks ==="
cf_stacks=$(aws cloudformation list-stacks --region "$AWS_REGION" \
    --query "StackSummaries[?contains(StackName, '${CLUSTER_NAME}') && StackStatus!='DELETE_COMPLETE'].{Name:StackName,Status:StackStatus}" \
    --output text 2>/dev/null || echo "")

if [[ -z "$cf_stacks" ]]; then
    pass "No active CloudFormation stacks for '${CLUSTER_NAME}'"
else
    fail "Lingering CloudFormation stacks:"
    echo "$cf_stacks" | while read -r line; do
        echo "       $line"
    done
fi
echo ""

# --- EBS Volumes ---
echo "=== EBS Volumes ==="
ebs_volumes=$(aws ec2 describe-volumes --region "$AWS_REGION" \
    --filters "Name=tag-key,Values=kubernetes.io/cluster/${CLUSTER_NAME}" \
    --query 'Volumes[].{ID:VolumeId,State:State,Size:Size}' \
    --output text 2>/dev/null || echo "")

if [[ -z "$ebs_volumes" ]]; then
    pass "No orphaned EBS volumes tagged for '${CLUSTER_NAME}'"
else
    fail "Orphaned EBS volumes:"
    echo "$ebs_volumes" | while read -r line; do
        echo "       $line"
    done
    echo ""
    echo -e "  ${YELLOW}Fix:${NC} aws ec2 delete-volume --volume-id <ID> --region ${AWS_REGION}"
fi
echo ""

# --- EFS Filesystems ---
echo "=== EFS Filesystems ==="
efs_filesystems=$(aws efs describe-file-systems --region "$AWS_REGION" \
    --query "FileSystems[?Tags[?Key=='kubernetes.io/cluster/${CLUSTER_NAME}' && Value=='owned']].{ID:FileSystemId,State:LifeCycleState}" \
    --output text 2>/dev/null || echo "")

if [[ -z "$efs_filesystems" ]]; then
    pass "No orphaned EFS filesystems for '${CLUSTER_NAME}'"
else
    fail "Orphaned EFS filesystems:"
    echo "$efs_filesystems" | while read -r line; do
        echo "       $line"
    done
    echo ""
    echo -e "  ${YELLOW}Fix:${NC} Delete mount targets first, then: aws efs delete-file-system --file-system-id <ID> --region ${AWS_REGION}"
fi
echo ""

# --- EFS Mount Targets (check even if no filesystem found — belt and suspenders) ---
echo "=== EFS Mount Targets ==="
efs_ids=$(aws efs describe-file-systems --region "$AWS_REGION" \
    --query "FileSystems[?Tags[?Key=='kubernetes.io/cluster/${CLUSTER_NAME}']].FileSystemId" \
    --output text 2>/dev/null || echo "")

if [[ -z "$efs_ids" ]]; then
    pass "No EFS mount targets to check (no tagged filesystems)"
else
    mt_found=false
    for fs_id in $efs_ids; do
        mt_ids=$(aws efs describe-mount-targets --file-system-id "$fs_id" --region "$AWS_REGION" \
            --query 'MountTargets[].MountTargetId' --output text 2>/dev/null || echo "")
        if [[ -n "$mt_ids" ]]; then
            mt_found=true
            fail "Lingering mount targets for ${fs_id}: ${mt_ids}"
        fi
    done
    if [[ "$mt_found" == "false" ]]; then
        pass "No lingering EFS mount targets"
    fi
fi
echo ""

# --- Security Groups ---
echo "=== Security Groups ==="
efs_sg=$(aws ec2 describe-security-groups --region "$AWS_REGION" \
    --filters "Name=group-name,Values=efs-${CLUSTER_NAME}" \
    --query 'SecurityGroups[].{ID:GroupId,Name:GroupName}' \
    --output text 2>/dev/null || echo "")

if [[ -z "$efs_sg" ]]; then
    pass "No orphaned EFS security group 'efs-${CLUSTER_NAME}'"
else
    fail "Orphaned security group: ${efs_sg}"
    echo -e "  ${YELLOW}Fix:${NC} aws ec2 delete-security-group --group-id <ID> --region ${AWS_REGION}"
fi
echo ""

# --- IAM Roles ---
echo "=== IAM Roles ==="
iam_roles=(
    "AmazonEKS_EBS_CSI_DriverRole_${CLUSTER_NAME}"
    "AmazonEKS_EFS_CSI_DriverRole_${CLUSTER_NAME}"
    "ClusterAutoscalerRole-${CLUSTER_NAME}"
)

for role in "${iam_roles[@]}"; do
    if aws iam get-role --role-name "$role" &>/dev/null; then
        fail "IAM role '${role}' still exists"
        echo -e "  ${YELLOW}Fix:${NC} Detach policies, then: aws iam delete-role --role-name ${role}"
    else
        pass "IAM role '${role}' not found"
    fi
done
echo ""

# --- IAM Policies ---
echo "=== IAM Policies ==="
account_id=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")
if [[ -n "$account_id" ]]; then
    policy_arn="arn:aws:iam::${account_id}:policy/ClusterAutoscalerPolicy-${CLUSTER_NAME}"
    if aws iam get-policy --policy-arn "$policy_arn" &>/dev/null; then
        fail "IAM policy 'ClusterAutoscalerPolicy-${CLUSTER_NAME}' still exists"
        echo -e "  ${YELLOW}Fix:${NC} aws iam delete-policy --policy-arn ${policy_arn}"
    else
        pass "IAM policy 'ClusterAutoscalerPolicy-${CLUSTER_NAME}' not found"
    fi
else
    fail "Could not determine AWS account ID"
fi
echo ""

# --- Load Balancers ---
echo "=== Load Balancers ==="
nlbs=$(aws elbv2 describe-load-balancers --region "$AWS_REGION" \
    --query "LoadBalancers[?contains(LoadBalancerName, '${CLUSTER_NAME}')].{Name:LoadBalancerName,ARN:LoadBalancerArn}" \
    --output text 2>/dev/null || echo "")

if [[ -z "$nlbs" ]]; then
    pass "No orphaned load balancers for '${CLUSTER_NAME}'"
else
    fail "Orphaned load balancers:"
    echo "$nlbs" | while read -r line; do
        echo "       $line"
    done
fi
echo ""

# --- Summary ---
echo "============================================"
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "============================================"

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo -e "${YELLOW}Some resources were not cleaned up. Use the Fix commands above to remove them manually.${NC}"
    exit 1
else
    echo ""
    echo -e "${GREEN}All clear — no lingering Nemesis resources found in ${AWS_REGION}.${NC}"
fi
