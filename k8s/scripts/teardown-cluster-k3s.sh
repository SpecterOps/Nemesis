#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-nemesis}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

KEEP_K3S=false
for arg in "$@"; do
    case "$arg" in
        --keep-k3s) KEEP_K3S=true ;;
        -h|--help)
            echo "Usage: $0 [--keep-k3s]"
            echo ""
            echo "Options:"
            echo "  --keep-k3s  Only remove Nemesis and Helm releases, keep k3s running"
            exit 0
            ;;
    esac
done

echo "============================================"
echo "  Nemesis K8s Cluster Teardown (k3s)"
echo "============================================"
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

if [[ "$KEEP_K3S" == "true" ]]; then
    log "Keeping k3s running (--keep-k3s). Only Helm releases were removed."
    log "Teardown complete"
    exit 0
fi

# Uninstall k3s
if [[ -x /usr/local/bin/k3s-uninstall.sh ]]; then
    log "Uninstalling k3s..."
    /usr/local/bin/k3s-uninstall.sh
else
    warn "k3s uninstall script not found at /usr/local/bin/k3s-uninstall.sh"
fi

log "Teardown complete"
