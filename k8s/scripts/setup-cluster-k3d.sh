#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$K8S_DIR")"

CLUSTER_NAME="${CLUSTER_NAME:-nemesis}"
REGISTRY_NAME="k3d-nemesis-registry.localhost"
REGISTRY_PORT="${REGISTRY_PORT:-5111}"
K3D_AGENTS="${K3D_AGENTS:-2}"
HTTPS_PORT="${HTTPS_PORT:-7443}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

check_prerequisites() {
    local missing=()

    for cmd in k3d kubectl helm; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing[*]}"
        echo ""
        echo "Install instructions:"
        echo "  k3d:    curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash"
        echo "  kubectl: https://kubernetes.io/docs/tasks/tools/"
        echo "  helm:   curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash"
        exit 1
    fi

    log "All prerequisites found"
}

create_registry() {
    if k3d registry list 2>/dev/null | grep -q "$REGISTRY_NAME"; then
        warn "Registry $REGISTRY_NAME already exists, skipping"
    else
        log "Creating local registry: $REGISTRY_NAME:$REGISTRY_PORT"
        k3d registry create nemesis-registry.localhost --port "$REGISTRY_PORT"
    fi

    # Ensure the registry hostname resolves (required for docker push)
    if ! grep -q "$REGISTRY_NAME" /etc/hosts 2>/dev/null; then
        log "Adding $REGISTRY_NAME to /etc/hosts (requires sudo)"
        echo "127.0.0.1 $REGISTRY_NAME" | sudo tee -a /etc/hosts >/dev/null
    fi
}

create_cluster() {
    if k3d cluster list 2>/dev/null | grep -q "$CLUSTER_NAME"; then
        warn "Cluster $CLUSTER_NAME already exists, skipping"
        return
    fi

    log "Creating k3d cluster: $CLUSTER_NAME (agents: $K3D_AGENTS, HTTPS port: $HTTPS_PORT)"
    k3d cluster create "$CLUSTER_NAME" \
        --port "${HTTPS_PORT}:443@loadbalancer" \
        --agents "$K3D_AGENTS" \
        --registry-use "$REGISTRY_NAME:$REGISTRY_PORT" \
        --k3s-arg "--disable=traefik@server:0" \
        --wait

    log "Waiting for cluster to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=120s
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
        --set "ports.websecure.nodePort=30443" \
        --set "ports.websecure.expose.default=true" \
        --set "ports.web.redirections.entryPoint.to=websecure" \
        --set "ports.web.redirections.entryPoint.scheme=https" \
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
        --version 1.17.0 \
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

    # Generate self-signed certs
    log "Generating self-signed TLS certificate..."
    local tmp_dir
    tmp_dir=$(mktemp -d)
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
        -keyout "$tmp_dir/tls.key" -out "$tmp_dir/tls.crt" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    kubectl create secret tls nemesis-tls-secret \
        --namespace nemesis \
        --cert="$tmp_dir/tls.crt" \
        --key="$tmp_dir/tls.key"

    rm -rf "$tmp_dir"
    log "TLS secret created with self-signed cert"
}

main() {
    echo "============================================"
    echo "  Nemesis K8s Cluster Setup"
    echo "============================================"
    echo ""

    check_prerequisites
    create_registry
    create_cluster
    install_traefik
    install_dapr
    install_keda
    create_namespace
    create_tls_secret

    echo ""
    log "Setup complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Build and push images:  ./k8s/scripts/build-and-push-k3d.sh"
    echo "  2. Deploy Nemesis:         ./k8s/scripts/deploy.sh"
    echo "  3. Verify deployment:      ./k8s/scripts/verify.sh"
    echo ""
    echo "Cluster info:"
    echo "  Name:     $CLUSTER_NAME"
    echo "  Registry: $REGISTRY_NAME:$REGISTRY_PORT"
    echo "  HTTPS:    https://localhost:$HTTPS_PORT"
}

main "$@"
