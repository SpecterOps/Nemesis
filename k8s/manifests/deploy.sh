#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K8S_DIR="$(dirname "$SCRIPT_DIR")"
HELM_FILES_DIR="${K8S_DIR}/helm/nemesis/files"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

usage() {
    cat <<EOF
Deploy Nemesis to a Kubernetes cluster using raw manifests (no Helm required).

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
  --config FILE  Use a custom config.env file (default: config.env next to this script)
  --dry-run      Render templates and print without applying
  -h, --help     Show this help

Examples:
  $0 install                              # Deploy using ghcr.io images
  $0 install --build                      # Build locally (k3d/k3s)
  $0 install --monitoring --jupyter --llm # Deploy with all optional stacks
  $0 install --dry-run                    # Preview rendered YAML
  $0 uninstall                            # Remove deployment
  $0 status                               # Check pod/service status
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
CONFIG_FILE="${SCRIPT_DIR}/config.env"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build) BUILD=true; shift ;;
        --monitoring) MONITORING=true; shift ;;
        --jupyter) JUPYTER=true; shift ;;
        --llm) LLM=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --config) CONFIG_FILE="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) error "Unknown option: $1"; usage ;;
    esac
done

# ---------------------------------------------------------------------------
# Source configuration
# ---------------------------------------------------------------------------
if [[ ! -f "$CONFIG_FILE" ]]; then
    error "Config file not found: $CONFIG_FILE"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

# Compute derived values
if [[ "$MONITORING" == "true" ]]; then
    export MONITORING_ENABLED="true"
    export NEMESIS_MONITORING="enabled"
else
    export MONITORING_ENABLED="false"
    export NEMESIS_MONITORING="disabled"
fi

# Export all variables for envsubst
set -a
# shellcheck source=/dev/null
source "$CONFIG_FILE"
set +a
export NEMESIS_MONITORING

# Build explicit envsubst variable list from config.env variable names + derived vars.
# This prevents envsubst from substituting ${VAR} patterns meant for runtime resolution
# (e.g., SeaweedFS entrypoint's ${S3_ACCESS_KEY} which is resolved by the container, not by us).
ENVSUBST_VARS="$(grep -oP '^\s*[A-Z_][A-Z0-9_]*(?==)' "$CONFIG_FILE" | sed 's/^/\$/' | tr '\n' ' ')"
ENVSUBST_VARS+=' $NEMESIS_MONITORING'
export ENVSUBST_VARS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Create a temp dir that gets cleaned up on exit
TMPDIR_RENDERED="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_RENDERED"' EXIT

# Run envsubst on a single YAML file into the temp dir, preserving subdirectory structure.
render_file() {
    local src="$1"
    local rel="${src#"$SCRIPT_DIR"/}"
    local dest="${TMPDIR_RENDERED}/${rel}"
    mkdir -p "$(dirname "$dest")"
    envsubst "$ENVSUBST_VARS" < "$src" > "$dest"
}

# Render all YAML files in a directory.
render_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        return
    fi
    while IFS= read -r -d '' f; do
        render_file "$f"
    done < <(find "$dir" -name '*.yaml' -print0 | sort -z)
}

# Apply (or print) all rendered YAML in a directory.
apply_dir() {
    local dir="$1"
    local rendered_dir="${TMPDIR_RENDERED}/${dir#"$SCRIPT_DIR"/}"
    if [[ ! -d "$rendered_dir" ]]; then
        return
    fi
    local files
    files=$(find "$rendered_dir" -name '*.yaml' | sort)
    if [[ -z "$files" ]]; then
        return
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
        for f in $files; do
            echo "---"
            echo "# Source: ${f#"$TMPDIR_RENDERED"/}"
            cat "$f"
            echo ""
        done
    else
        for f in $files; do
            # Skip files that contain only comments/whitespace (no YAML objects)
            if grep -qE '^\s*[^#[:space:]]' "$f"; then
                kubectl apply -f "$f"
            fi
        done
    fi
}

# Inline a file's content into a YAML placeholder (indented with 4 spaces).
inline_file() {
    local rendered_yaml="$1"
    local placeholder="$2"
    local source_file="$3"

    if [[ ! -f "$source_file" ]]; then
        warn "File not found for inlining: $source_file"
        return
    fi

    # Create indented content (4 spaces for YAML data block)
    local indented
    indented=$(sed 's/^/    /' "$source_file")

    # Use a temp file for the replacement to handle large files
    local tmpfile
    tmpfile=$(mktemp)
    awk -v placeholder="$placeholder" -v replacement="$indented" '
    {
        idx = index($0, placeholder)
        if (idx > 0) {
            print replacement
        } else {
            print
        }
    }' "$rendered_yaml" > "$tmpfile"
    mv "$tmpfile" "$rendered_yaml"
}

# Inline a file's base64-encoded content for binaryData fields.
inline_file_b64() {
    local rendered_yaml="$1"
    local placeholder="$2"
    local source_file="$3"

    if [[ ! -f "$source_file" ]]; then
        warn "File not found for base64 inlining: $source_file"
        return
    fi

    # Write base64 to a temp file to avoid argument-list-too-long errors
    local b64file
    b64file=$(mktemp)
    base64 -w0 < "$source_file" > "$b64file"

    local tmpfile
    tmpfile=$(mktemp)
    awk -v placeholder="$placeholder" -v b64file="$b64file" '
    {
        idx = index($0, placeholder)
        if (idx > 0) {
            # Read replacement from file
            getline replacement < b64file
            close(b64file)
            gsub(placeholder, replacement)
        }
        print
    }' "$rendered_yaml" > "$tmpfile"
    mv "$tmpfile" "$rendered_yaml"
    rm -f "$b64file"
}

# ---------------------------------------------------------------------------
# Post-render: inline external files into ConfigMap placeholders
# ---------------------------------------------------------------------------
post_render() {
    # Postgres init SQL files
    local pg_init="${TMPDIR_RENDERED}/base/configmap-postgres-init.yaml"
    if [[ -f "$pg_init" ]]; then
        inline_file "$pg_init" "__PLACEHOLDER_01_SCHEMA_SQL__" "${HELM_FILES_DIR}/01-schema.sql"
        inline_file "$pg_init" "__PLACEHOLDER_02_SEED_SQL__" "${HELM_FILES_DIR}/02-seed.sql"
    fi

    # Tika config files
    local tika="${TMPDIR_RENDERED}/base/configmap-tika.yaml"
    if [[ -f "$tika" ]]; then
        inline_file "$tika" "__PLACEHOLDER_TIKA_CONFIG_XML__" "${HELM_FILES_DIR}/tika-config.xml"
        inline_file "$tika" "__PLACEHOLDER_TIKA_CONFIG_TESSERACT_XML__" "${HELM_FILES_DIR}/tika-config-tesseract.xml"
    fi

    # RabbitMQ config files
    local rmq="${TMPDIR_RENDERED}/base/configmap-rabbitmq.yaml"
    if [[ -f "$rmq" ]]; then
        inline_file "$rmq" "__PLACEHOLDER_RABBITMQ_CONF__" "${HELM_FILES_DIR}/rabbitmq.conf"
        inline_file "$rmq" "__PLACEHOLDER_ENABLED_PLUGINS__" "${HELM_FILES_DIR}/enabled_plugins"
    fi

    # Hasura metadata files
    local hasura="${TMPDIR_RENDERED}/infra/hasura.yaml"
    if [[ -f "$hasura" ]]; then
        inline_file "$hasura" "__PLACEHOLDER_DATABASES_YAML__" "${HELM_FILES_DIR}/databases.yaml"
        inline_file "$hasura" "__PLACEHOLDER_FUNCTIONS_YAML__" "${HELM_FILES_DIR}/functions.yaml"
        inline_file "$hasura" "__PLACEHOLDER_TABLES_YAML__" "${HELM_FILES_DIR}/tables.yaml"
        inline_file "$hasura" "__PLACEHOLDER_VERSION_YAML__" "${HELM_FILES_DIR}/version.yaml"
    fi

    # Grafana dashboard files (base64 for binaryData)
    if [[ "$MONITORING" == "true" ]]; then
        local dashboards="${TMPDIR_RENDERED}/monitoring/grafana-dashboards.yaml"
        if [[ -f "$dashboards" ]]; then
            inline_file_b64 "$dashboards" "__PLACEHOLDER_TRAEFIK_DASHBOARD__" "${HELM_FILES_DIR}/grafana-dashboards/traefik.json"
            inline_file_b64 "$dashboards" "__PLACEHOLDER_SEAWEEDFS_DASHBOARD__" "${HELM_FILES_DIR}/grafana-dashboards/seaweedfs.json"
            inline_file_b64 "$dashboards" "__PLACEHOLDER_NODE_EXPORTER_DASHBOARD__" "${HELM_FILES_DIR}/grafana-dashboards/node_exporter_full.json"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

do_install() {
    # Verify namespace exists
    if ! kubectl get namespace "${NAMESPACE}" &>/dev/null; then
        if [[ "$DRY_RUN" != "true" ]]; then
            log "Creating namespace: ${NAMESPACE}"
            kubectl create namespace "${NAMESPACE}"
            kubectl label namespace "${NAMESPACE}" dapr.io/inject=true --overwrite
        fi
    fi

    # Build images if requested
    if [[ "$BUILD" == "true" ]]; then
        local registry="${REGISTRY:-k3d-nemesis-registry.localhost:5111}"
        if curl -sf "http://${registry}/v2/" &>/dev/null; then
            log "Detected k3d registry at ${registry}"
            log "Building and pushing images to k3d registry..."
            "${K8S_DIR}/scripts/build-and-push-k3d.sh"
            export IMAGE_REGISTRY="${registry}"
            export IMAGE_PULL_POLICY="Always"
        elif command -v k3s &>/dev/null; then
            log "Detected k3s cluster"
            log "Building images and loading into k3s containerd..."
            "${K8S_DIR}/scripts/build-and-load-k3s.sh"
            export IMAGE_REGISTRY="nemesis"
            export IMAGE_PULL_POLICY="Never"
        else
            error "--build requires either a k3d cluster with a local registry or a k3s installation."
            exit 1
        fi
    fi

    log "Rendering manifests..."

    # Render core directories
    render_dir "${SCRIPT_DIR}/base"
    render_dir "${SCRIPT_DIR}/infra"
    render_dir "${SCRIPT_DIR}/apps"
    render_dir "${SCRIPT_DIR}/dapr"
    render_dir "${SCRIPT_DIR}/ingress"
    if [[ "$AUTOSCALING_ENABLED" == "true" ]]; then
        render_file "${SCRIPT_DIR}/keda/triggerauthentication.yaml"
        [[ "$KEDA_FILE_ENRICHMENT_ENABLED" == "true" ]] && render_file "${SCRIPT_DIR}/keda/scaledobject-file-enrichment.yaml"
        [[ "$KEDA_DOCUMENT_CONVERSION_ENABLED" == "true" ]] && render_file "${SCRIPT_DIR}/keda/scaledobject-document-conversion.yaml"
        [[ "$KEDA_TITUS_SCANNER_ENABLED" == "true" ]] && render_file "${SCRIPT_DIR}/keda/scaledobject-titus-scanner.yaml"
        [[ "$KEDA_DOTNET_SERVICE_ENABLED" == "true" ]] && render_file "${SCRIPT_DIR}/keda/scaledobject-dotnet-service.yaml"
        [[ "$KEDA_GOTENBERG_ENABLED" == "true" ]] && render_file "${SCRIPT_DIR}/keda/scaledobject-gotenberg.yaml"
    fi

    # Render optional stacks
    if [[ "$MONITORING" == "true" ]]; then
        render_dir "${SCRIPT_DIR}/monitoring"
    fi
    if [[ "$JUPYTER" == "true" ]]; then
        render_dir "${SCRIPT_DIR}/jupyter"
    fi
    if [[ "$LLM" == "true" ]]; then
        render_dir "${SCRIPT_DIR}/llm"
    fi

    # Inline external file content into rendered ConfigMaps
    post_render

    log "Applying manifests to namespace: ${NAMESPACE}"

    # Apply in dependency order
    apply_dir "${SCRIPT_DIR}/base"
    apply_dir "${SCRIPT_DIR}/dapr"
    apply_dir "${SCRIPT_DIR}/infra"
    apply_dir "${SCRIPT_DIR}/apps"
    apply_dir "${SCRIPT_DIR}/ingress"
    if [[ "$AUTOSCALING_ENABLED" == "true" ]]; then
        apply_dir "${SCRIPT_DIR}/keda"
    fi

    # Apply optional stacks
    if [[ "$MONITORING" == "true" ]]; then
        log "Applying monitoring stack..."
        apply_dir "${SCRIPT_DIR}/monitoring"
    fi
    if [[ "$JUPYTER" == "true" ]]; then
        log "Applying Jupyter stack..."
        apply_dir "${SCRIPT_DIR}/jupyter"
    fi
    if [[ "$LLM" == "true" ]]; then
        log "Applying LLM stack..."
        apply_dir "${SCRIPT_DIR}/llm"
    fi

    if [[ "$DRY_RUN" != "true" ]]; then
        echo ""
        log "Deployment complete!"
        echo ""
        do_status
    fi
}

do_uninstall() {
    log "Uninstalling Nemesis from namespace: ${NAMESPACE}"

    # Delete optional stacks first (reverse order)
    kubectl delete ingressroute -n "${NAMESPACE}" nemesis-llm-ingress 2>/dev/null || true
    kubectl delete ingressroute -n "${NAMESPACE}" nemesis-jupyter-ingress 2>/dev/null || true
    kubectl delete ingressroute -n "${NAMESPACE}" nemesis-monitoring-ingress 2>/dev/null || true
    kubectl delete ingressroute -n "${NAMESPACE}" nemesis-ingress 2>/dev/null || true

    # Delete KEDA objects
    kubectl delete scaledobject -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true
    kubectl delete triggerauthentication -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true

    # Delete Dapr components
    kubectl delete component -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true
    kubectl delete configuration -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true

    # Delete all workloads
    kubectl delete deployment -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true
    kubectl delete statefulset -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true
    kubectl delete daemonset -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true
    kubectl delete job -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true

    # Delete services, configmaps, secrets, middleware
    kubectl delete service -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true
    kubectl delete configmap -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true
    kubectl delete secret -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true
    kubectl delete middleware -l app.kubernetes.io/part-of=nemesis -n "${NAMESPACE}" 2>/dev/null || true

    # Clean up cluster-scoped resources
    kubectl delete clusterrole "${NAMESPACE}-promtail" 2>/dev/null || true
    kubectl delete clusterrolebinding "${NAMESPACE}-promtail" 2>/dev/null || true

    log "Uninstall complete. PVCs are retained — delete manually if needed:"
    echo "  kubectl delete pvc --all -n ${NAMESPACE}"
}

do_status() {
    echo "=== Pods ==="
    kubectl get pods -n "${NAMESPACE}" -o wide 2>/dev/null || warn "No pods found"
    echo ""
    echo "=== Services ==="
    kubectl get svc -n "${NAMESPACE}" 2>/dev/null || warn "No services found"
    echo ""
    echo "=== Dapr Components ==="
    kubectl get components.dapr.io -n "${NAMESPACE}" 2>/dev/null || warn "No Dapr components found"
    echo ""
    echo "=== KEDA ScaledObjects ==="
    kubectl get scaledobject -n "${NAMESPACE}" 2>/dev/null || warn "No KEDA objects found"
}

case "$ACTION" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    status)    do_status ;;
    *)         error "Unknown action: $ACTION"; usage ;;
esac
