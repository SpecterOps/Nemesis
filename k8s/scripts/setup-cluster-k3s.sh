#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$K8S_DIR")"

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

    for cmd in curl kubectl helm; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing[*]}"
        echo ""
        echo "Install instructions:"
        echo "  curl:    apt install curl / yum install curl"
        echo "  kubectl: https://kubernetes.io/docs/tasks/tools/"
        echo "  helm:    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash"
        exit 1
    fi

    log "All prerequisites found"
}

install_k3s() {
    if command -v k3s &>/dev/null && k3s kubectl get nodes &>/dev/null 2>&1; then
        warn "k3s is already installed and running, skipping installation"
        return
    fi

    log "Installing k3s (disabling built-in Traefik)..."
    curl -sfL https://get.k3s.io | sh -s - --disable=traefik

    log "k3s installed"
}

configure_kubeconfig() {
    log "Configuring kubeconfig..."

    # Wait for k3s kubeconfig to appear
    local retries=0
    while [[ ! -f /etc/rancher/k3s/k3s.yaml ]] && [[ $retries -lt 30 ]]; do
        sleep 1
        ((retries++))
    done

    if [[ ! -f /etc/rancher/k3s/k3s.yaml ]]; then
        error "k3s kubeconfig not found at /etc/rancher/k3s/k3s.yaml after 30s"
        exit 1
    fi

    mkdir -p "$HOME/.kube"

    # Back up existing kubeconfig if present
    if [[ -f "$HOME/.kube/config" ]]; then
        warn "Backing up existing kubeconfig to $HOME/.kube/config.bak"
        cp "$HOME/.kube/config" "$HOME/.kube/config.bak"
    fi

    sudo cp /etc/rancher/k3s/k3s.yaml "$HOME/.kube/config"
    sudo chown "$(id -u):$(id -g)" "$HOME/.kube/config"
    chmod 600 "$HOME/.kube/config"

    log "Kubeconfig configured at $HOME/.kube/config"
}

wait_for_node() {
    log "Waiting for k3s node to register..."
    local retries=0
    while ! kubectl get nodes &>/dev/null || [[ $(kubectl get nodes --no-headers 2>/dev/null | wc -l) -eq 0 ]]; do
        if [[ $retries -ge 30 ]]; then
            error "No nodes registered after 30s"
            exit 1
        fi
        sleep 1
        ((retries++))
    done

    log "Node registered, waiting for Ready status..."
    kubectl wait --for=condition=Ready nodes --all --timeout=120s
    log "Node is ready"
}

install_traefik() {
    log "Installing Traefik via Helm..."
    helm repo add traefik https://traefik.github.io/charts 2>/dev/null || true
    helm repo update traefik

    if helm status traefik -n kube-system &>/dev/null; then
        warn "Traefik already installed, skipping"
        return
    fi

    # k3s has built-in ServiceLB (Klipper), so we use LoadBalancer service type
    helm install traefik traefik/traefik \
        --namespace kube-system \
        --version 34.3.0 \
        --set "service.type=LoadBalancer" \
        --set "ports.websecure.expose.default=true" \
        --set "ports.websecure.exposedPort=7443" \
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
    echo "  Nemesis K8s Cluster Setup (k3s)"
    echo "============================================"
    echo ""

    check_prerequisites
    install_k3s
    configure_kubeconfig
    wait_for_node
    install_traefik
    install_dapr
    install_keda
    create_namespace
    create_tls_secret

    echo ""
    log "Setup complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Deploy Nemesis:         ./k8s/scripts/deploy.sh install"
    echo "     Or build from source:   ./k8s/scripts/deploy.sh install --build"
    echo "  2. Verify deployment:      ./k8s/scripts/verify.sh"
    echo ""
    echo "Cluster info:"
    echo "  Runtime: k3s"
    echo "  HTTPS:   https://localhost:${HTTPS_PORT}"
    echo ""
    echo "Note: --build requires Docker to build images, which are then loaded"
    echo "      into k3s containerd via 'k3s ctr images import'."
}

main "$@"
