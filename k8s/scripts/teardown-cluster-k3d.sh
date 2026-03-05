#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-nemesis}"
REGISTRY_NAME="k3d-nemesis-registry.localhost"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }

REMOVE_REGISTRY=false
for arg in "$@"; do
    case "$arg" in
        --registry) REMOVE_REGISTRY=true ;;
        -h|--help)
            echo "Usage: $0 [--registry]"
            echo ""
            echo "Options:"
            echo "  --registry  Also remove the k3d local registry"
            exit 0
            ;;
    esac
done

echo "============================================"
echo "  Nemesis K8s Cluster Teardown"
echo "============================================"
echo ""

if k3d cluster list 2>/dev/null | grep -q "$CLUSTER_NAME"; then
    log "Deleting k3d cluster: $CLUSTER_NAME"
    k3d cluster delete "$CLUSTER_NAME"
else
    warn "Cluster $CLUSTER_NAME not found"
fi

if [[ "$REMOVE_REGISTRY" == "true" ]]; then
    if k3d registry list 2>/dev/null | grep -q "nemesis-registry"; then
        log "Deleting registry: $REGISTRY_NAME"
        k3d registry delete nemesis-registry.localhost
    else
        warn "Registry not found"
    fi
fi

log "Teardown complete"
