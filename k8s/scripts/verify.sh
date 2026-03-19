#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-nemesis}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass()  { echo -e "  ${GREEN}PASS${NC} $*"; ((PASS++)) || true; }
fail()  { echo -e "  ${RED}FAIL${NC} $*"; ((FAIL++)) || true; }
warn_() { echo -e "  ${YELLOW}WARN${NC} $*"; ((WARN++)) || true; }

check_pods() {
    echo "=== Pod Status ==="
    local not_ready
    not_ready=$(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | grep -v -E "Running|Completed" || true)

    if [[ -z "$not_ready" ]]; then
        pass "All pods are Running/Completed"
    else
        fail "Some pods are not ready:"
        echo "$not_ready" | while read -r line; do
            echo "       $line"
        done
    fi

    local total
    total=$(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)
    echo "  Total pods: $total"
    echo ""
}

check_dapr_components() {
    echo "=== Dapr Components ==="
    local components
    components=$(kubectl get components.dapr.io -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)

    if [[ "$components" -ge 9 ]]; then
        pass "Found $components Dapr components (expected >= 9: 1 secretstore + 1 statestore + 7 pubsub)"
    else
        fail "Found only $components Dapr components (expected >= 9)"
    fi

    # Check configurations
    local configs
    configs=$(kubectl get configurations.dapr.io -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)
    if [[ "$configs" -ge 4 ]]; then
        pass "Found $configs Dapr configurations (expected >= 4)"
    else
        fail "Found only $configs Dapr configurations (expected >= 4)"
    fi
    echo ""
}

check_keda() {
    echo "=== KEDA ScaledObjects ==="
    local scaled
    scaled=$(kubectl get scaledobject -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)

    if [[ "$scaled" -ge 2 ]]; then
        pass "Found $scaled ScaledObjects (expected >= 2)"
    else
        warn_ "Found $scaled ScaledObjects (expected >= 2, check autoscaling.enabled)"
    fi
    echo ""
}

check_services() {
    echo "=== Services ==="
    local expected_services=(postgres rabbitmq seaweedfs hasura web-api file-enrichment document-conversion frontend gotenberg)

    for svc in "${expected_services[@]}"; do
        if kubectl get svc "$svc" -n "$NAMESPACE" &>/dev/null; then
            pass "Service $svc exists"
        else
            fail "Service $svc not found"
        fi
    done
    echo ""
}

check_health_endpoints() {
    echo "=== Health Endpoints ==="

    # Port-forward and check web-api health (background)
    local pf_pid=""
    kubectl port-forward svc/web-api 18000:8000 -n "$NAMESPACE" &>/dev/null &
    pf_pid=$!
    sleep 3

    if curl -s --max-time 5 "http://localhost:18000/api/healthz" &>/dev/null; then
        pass "web-api /api/healthz responds"
    else
        warn_ "web-api /api/healthz not reachable (may need more startup time)"
    fi

    kill "$pf_pid" 2>/dev/null || true
    wait "$pf_pid" 2>/dev/null || true
    echo ""
}

check_ingress() {
    echo "=== Ingress ==="
    if kubectl get ingressroute -n "$NAMESPACE" &>/dev/null; then
        local routes
        routes=$(kubectl get ingressroute -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)
        pass "Found $routes IngressRoute(s)"
    else
        warn_ "No IngressRoute CRD available (Traefik CRDs may not be installed)"
    fi
    echo ""
}

main() {
    echo "============================================"
    echo "  Nemesis Deployment Verification"
    echo "  Namespace: $NAMESPACE"
    echo "============================================"
    echo ""

    check_pods
    check_services
    check_dapr_components
    check_keda
    check_ingress
    check_health_endpoints

    echo "============================================"
    echo "  Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$WARN warnings${NC}"
    echo "============================================"

    if [[ $FAIL -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
