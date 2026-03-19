#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$K8S_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

# Services to build (name:dockerfile_path:context)
# Most use repo root as context (Dockerfiles COPY from ./libs, ./projects).
# Frontend and titus-scanner use their own project dir as context.
SERVICES=(
    "web-api:projects/web_api/Dockerfile:."
    "file-enrichment:projects/file_enrichment/Dockerfile:."
    "document-conversion:projects/document_conversion/Dockerfile:."
    "titus-scanner:projects/titus_scanner/Dockerfile:."
    "dotnet-service:projects/dotnet_service/Dockerfile:."
    "alerting:projects/alerting/Dockerfile:."
    "housekeeping:projects/housekeeping/Dockerfile:."
    "frontend:projects/frontend/Dockerfile:projects/frontend"
    "agents:projects/agents/Dockerfile:."
    "jupyter:projects/jupyter/Dockerfile:projects/jupyter"
)

usage() {
    cat <<EOF
Build Nemesis images and load them into k3s containerd.

Usage: $0 [options] [service...]

Options:
  --parallel           Build images in parallel
  -h, --help           Show this help

Examples:
  $0                   # Build all services
  $0 web-api frontend  # Build specific services
  $0 --parallel        # Build all in parallel
EOF
    exit 0
}

PARALLEL=false
SELECTED_SERVICES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --parallel) PARALLEL=true; shift ;;
        -h|--help) usage ;;
        *)
            SELECTED_SERVICES+=("$1")
            shift
            ;;
    esac
done

# Verify k3s is available
if ! command -v k3s &>/dev/null; then
    error "k3s is not installed. Run setup-cluster-k3s.sh first."
    exit 1
fi

# Verify docker is available (needed to build images)
if ! command -v docker &>/dev/null; then
    error "docker is required to build images. Install Docker to use --build with k3s."
    exit 1
fi

cd "$REPO_ROOT"

# Build base images first
log "Building base images..."
docker compose -f compose.base.yaml build

# Generate version.json
if [[ -f "$REPO_ROOT/tools/generate-version.sh" ]]; then
    "$REPO_ROOT/tools/generate-version.sh" "$REPO_ROOT/version.json" "k8s-local"
fi

import_image() {
    local tag="$1"
    log "Importing $tag into k3s containerd..."
    docker save "$tag" | sudo k3s ctr images import -
}

build_service() {
    local name="$1"
    local dockerfile="$2"
    local context="$3"
    local tag="docker.io/nemesis/${name}:latest"

    if [[ ! -f "$dockerfile" ]]; then
        warn "Dockerfile not found at $dockerfile, skipping $name"
        return 0
    fi

    log "Building $name -> $tag"
    docker build -t "$tag" -f "$dockerfile" "$context"

    import_image "$tag"
}

build_count=0
for entry in "${SERVICES[@]}"; do
    IFS=: read -r name dockerfile context <<< "$entry"

    # If specific services were selected, skip others
    if [[ ${#SELECTED_SERVICES[@]} -gt 0 ]]; then
        skip=true
        for selected in "${SELECTED_SERVICES[@]}"; do
            if [[ "$selected" == "$name" ]]; then
                skip=false
                break
            fi
        done
        if [[ "$skip" == "true" ]]; then
            continue
        fi
    fi

    if [[ "$PARALLEL" == "true" ]]; then
        build_service "$name" "$dockerfile" "$context" &
    else
        build_service "$name" "$dockerfile" "$context"
    fi
    ((build_count++)) || true
done

if [[ "$PARALLEL" == "true" ]]; then
    log "Waiting for parallel builds to complete..."
    wait
fi

# Import external images into k3s containerd.
# These are third-party images referenced in values.yaml that aren't built from source.
EXTERNAL_IMAGES=(
    "public.ecr.aws/bitnami/pgbouncer:1.25.1"
)

if [[ ${#SELECTED_SERVICES[@]} -eq 0 ]]; then
    for image in "${EXTERNAL_IMAGES[@]}"; do
        log "Pulling ${image}..."
        docker pull "${image}"
        import_image "${image}"
    done
fi

log "Built and loaded $build_count images into k3s containerd"
