#!/usr/bin/env bash
set -euo pipefail
#
# Compares infrastructure image tags between compose.yaml and Helm values.yaml.
# Exits non-zero if any versions are out of sync.
# No external dependencies beyond grep/sed.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

COMPOSE="${REPO_ROOT}/compose.yaml"
VALUES="${REPO_ROOT}/k8s/helm/nemesis/values.yaml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

DRIFT=0

# Extract tag after the last colon from compose image line
compose_tag() {
    grep -m1 "image:.*${1}" "$COMPOSE" | sed 's/.*:\([^"]*\).*/\1/' | tr -d ' '
}

# Extract a tag value from values.yaml by grepping for a key
# Usage: values_tag "tag:" "context_pattern"
#   context_pattern: a unique line appearing before the tag line (section header)
values_tag_after() {
    local key="$1"
    local section="$2"
    # Find the line number of the section, then find the first "tag:" after it
    local section_line
    section_line=$(grep -n "$section" "$VALUES" | head -1 | cut -d: -f1)
    if [[ -z "$section_line" ]]; then
        echo ""
        return
    fi
    tail -n +"$section_line" "$VALUES" | grep -m1 "$key" | sed 's/.*: *//' | tr -d '"'"' "
}

# check <label> <compose_image_pattern> <values_section_pattern> [values_key]
check() {
    local label="$1"
    local compose_pattern="$2"
    local section="$3"
    local key="${4:-tag:}"

    local ctag vtag
    ctag=$(compose_tag "$compose_pattern")
    vtag=$(values_tag_after "$key" "$section")

    if [[ -z "$ctag" ]]; then
        echo -e "${YELLOW}[?]${NC} ${label}: not found in compose.yaml"
        return
    fi
    if [[ -z "$vtag" ]]; then
        echo -e "${YELLOW}[?]${NC} ${label}: not found in values.yaml"
        return
    fi

    if [[ "$ctag" == "$vtag" ]]; then
        echo -e "${GREEN}[=]${NC} ${label}: ${ctag}"
    else
        echo -e "${RED}[x]${NC} ${label}: compose=${ctag}  helm=${vtag}"
        DRIFT=1
    fi
}

# Special case: dapr sidecar is stored as a full image string in values.yaml
check_dapr() {
    local ctag vtag
    ctag=$(compose_tag "daprio/daprd:")
    vtag=$(grep 'sidecarImage:' "$VALUES" | sed 's/.*://' | tr -d '"'" ")

    if [[ "$ctag" == "$vtag" ]]; then
        echo -e "${GREEN}[=]${NC} Dapr sidecar: ${ctag}"
    else
        echo -e "${RED}[x]${NC} Dapr sidecar: compose=${ctag}  helm=${vtag}"
        DRIFT=1
    fi
}

echo "Comparing image tags: compose.yaml vs k8s/helm/nemesis/values.yaml"
echo ""

check "PostgreSQL"  "postgres:"              "^postgres:"
check "RabbitMQ"    "rabbitmq:"              "^rabbitmq:"
check "SeaweedFS"   "chrislusf/seaweedfs:"   "^seaweedfs:"
check "Hasura"      "hasura/graphql-engine:"  "^hasura:"
check "Gotenberg"   "gotenberg/gotenberg:"    "^gotenberg:"
check_dapr

echo ""

if [[ "$DRIFT" -eq 0 ]]; then
    echo -e "${GREEN}All image tags are in sync.${NC}"
else
    echo -e "${RED}Image tag drift detected! Update the out-of-sync values above.${NC}"
    exit 1
fi
