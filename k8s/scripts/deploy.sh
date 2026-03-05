#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(dirname "$SCRIPT_DIR")"
CHART_DIR="${K8S_DIR}/helm/nemesis"

NAMESPACE="${NAMESPACE:-nemesis}"
RELEASE_NAME="${RELEASE_NAME:-nemesis}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

usage() {
    cat <<EOF
Deploy Nemesis to a Kubernetes cluster using Helm.

Usage: $0 <action> [options]

Actions:
  install       Install/upgrade Nemesis
  uninstall     Uninstall Nemesis
  status        Show deployment status

Options:
  --build        Build images locally before deploying (auto-detects k3d or k3s)
  --monitoring   Enable monitoring stack (Prometheus, Grafana, Loki, Jaeger, etc.)
  --jupyter      Enable Jupyter notebook stack
  --llm          Enable LLM stack (LiteLLM, Phoenix, Agents)
  --values FILE  Additional values file
  --set KEY=VAL  Override a specific value
  --dry-run      Render templates without deploying
  -h, --help     Show this help

Examples:
  $0 install                     # Deploy using ghcr.io images
  $0 install --build             # Build locally (k3d registry or k3s ctr import)
  $0 install --monitoring        # Deploy with monitoring enabled
  $0 uninstall                   # Remove deployment
  $0 status                      # Check pod/service status
EOF
    exit 0
}

if [[ $# -lt 1 ]]; then
    usage
fi

ACTION="$1"
shift

BUILD=false
MONITORING=false
JUPYTER=false
LLM=false
DRY_RUN=false
EXTRA_VALUES=()
EXTRA_SETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build) BUILD=true; shift ;;
        --monitoring) MONITORING=true; shift ;;
        --jupyter) JUPYTER=true; shift ;;
        --llm) LLM=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --values) EXTRA_VALUES+=("$2"); shift 2 ;;
        --set) EXTRA_SETS+=("$2"); shift 2 ;;
        -h|--help) usage ;;
        *) error "Unknown option: $1"; usage ;;
    esac
done

do_install() {
    # Verify namespace exists (created by setup-cluster-k3d.sh or setup-cluster-k3s.sh)
    if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
        error "Namespace '$NAMESPACE' does not exist. Run setup-cluster-k3d.sh or setup-cluster-k3s.sh first."
        exit 1
    fi

    log "Deploying Nemesis to namespace: $NAMESPACE"

    # Build images if requested (auto-detects k3d or k3s)
    if [[ "$BUILD" == "true" ]]; then
        local registry="${REGISTRY:-k3d-nemesis-registry.localhost:5111}"
        if curl -sf "http://${registry}/v2/" &>/dev/null; then
            BUILD_TARGET="k3d"
            log "Detected k3d registry at ${registry}"
            log "Building and pushing images to k3d registry..."
            "${SCRIPT_DIR}/build-and-push-k3d.sh"
        elif command -v k3s &>/dev/null; then
            BUILD_TARGET="k3s"
            log "Detected k3s cluster"
            log "Building images and loading into k3s containerd..."
            "${SCRIPT_DIR}/build-and-load-k3s.sh"
        else
            error "--build requires either a k3d cluster with a local registry or a k3s installation."
            error "Use setup-cluster-k3d.sh or setup-cluster-k3s.sh first, or deploy without --build to pull from ghcr.io."
            exit 1
        fi
    fi

    # Build helm command
    local -a HELM_CMD=(
        helm upgrade --install "$RELEASE_NAME" "$CHART_DIR"
        --namespace "$NAMESPACE"
        -f "${CHART_DIR}/values.yaml"
    )

    # Use dev values (local registry/containerd) when building locally
    if [[ "$BUILD" == "true" ]]; then
        if [[ "${BUILD_TARGET:-k3d}" == "k3s" ]]; then
            HELM_CMD+=(-f "${CHART_DIR}/values-dev-k3s.yaml")
        else
            HELM_CMD+=(-f "${CHART_DIR}/values-dev.yaml")
        fi
    fi

    # Optional stack toggles
    if [[ "$MONITORING" == "true" ]]; then
        HELM_CMD+=(--set "monitoring.enabled=true")
    fi
    if [[ "$JUPYTER" == "true" ]]; then
        HELM_CMD+=(--set "jupyter.enabled=true")
    fi
    if [[ "$LLM" == "true" ]]; then
        HELM_CMD+=(--set "llm.enabled=true")
    fi

    # Extra values files
    for f in "${EXTRA_VALUES[@]+"${EXTRA_VALUES[@]}"}"; do
        HELM_CMD+=(-f "$f")
    done

    # Extra --set overrides
    for s in "${EXTRA_SETS[@]+"${EXTRA_SETS[@]}"}"; do
        HELM_CMD+=(--set "$s")
    done

    if [[ "$DRY_RUN" == "true" ]]; then
        HELM_CMD+=(--dry-run --debug)
    else
        HELM_CMD+=(--wait --timeout 10m)
    fi

    echo ""
    log "Running: ${HELM_CMD[*]}"
    echo ""
    "${HELM_CMD[@]}"

    if [[ "$DRY_RUN" != "true" ]]; then
        echo ""
        log "Deployment complete!"
        echo ""
        do_status
    fi
}

do_uninstall() {
    log "Uninstalling Nemesis from namespace: $NAMESPACE"
    helm uninstall "$RELEASE_NAME" --namespace "$NAMESPACE" 2>/dev/null || warn "Release not found"
    log "Uninstall complete. PVCs are retained — delete manually if needed:"
    echo "  kubectl delete pvc --all -n $NAMESPACE"
}

do_status() {
    echo "=== Pods ==="
    kubectl get pods -n "$NAMESPACE" -o wide 2>/dev/null || warn "No pods found"
    echo ""
    echo "=== Services ==="
    kubectl get svc -n "$NAMESPACE" 2>/dev/null || warn "No services found"
    echo ""
    echo "=== Dapr Components ==="
    kubectl get components.dapr.io -n "$NAMESPACE" 2>/dev/null || warn "No Dapr components found"
    echo ""
    echo "=== KEDA ScaledObjects ==="
    kubectl get scaledobject -n "$NAMESPACE" 2>/dev/null || warn "No KEDA objects found"
}

case "$ACTION" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    status)    do_status ;;
    *)         error "Unknown action: $ACTION"; usage ;;
esac
