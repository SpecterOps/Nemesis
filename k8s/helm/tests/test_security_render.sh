#!/usr/bin/env bash
# Render-time security checks for the Nemesis Helm chart. Requires helm and python3 with PyYAML.
# Run: ./k8s/helm/tests/test_security_render.sh
set -euo pipefail

CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/../nemesis" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

render() { # render OUTFILE [helm args...]
  local out=$1
  shift
  helm template nemesis "$CHART" --set llm.enabled=true --set jupyter.enabled=true \
    --set monitoring.enabled=true "$@" > "$out"
}

render "$TMP/default.yaml"
render "$TMP/explicit.yaml" --set credentials.litellm.adminPassword=custom --set credentials.litellm.saltKey=sk-salt
render "$TMP/legacy.yaml" --set llm.litellm.env.litellmAdminPassword=legacy

python3 - "$TMP" <<'EOF'
import sys
from pathlib import Path

import yaml

tmp = Path(sys.argv[1])
failures = 0


def check(desc, cond):
    global failures
    print(("ok   - " if cond else "FAIL - ") + desc)
    failures += 0 if cond else 1


def docs(name):
    return [d for d in yaml.safe_load_all((tmp / name).read_text()) if d]


def find(objs, kind, name):
    return next(d for d in objs if d["kind"] == kind and d["metadata"]["name"] == name)


def container_env(deploy, container):
    c = next(c for c in deploy["spec"]["template"]["spec"]["containers"] if c["name"] == container)
    return {e["name"]: e for e in c.get("env", [])}


def secret_ref(env, name):
    return env[name].get("valueFrom", {}).get("secretKeyRef", {})


default = docs("default.yaml")
secrets = find(default, "Secret", "nemesis-secrets")["stringData"]

# --- NEM-SEC-005: LiteLLM keys ---
master, salt = secrets["LITELLM_MASTER_KEY"], secrets["LITELLM_SALT_KEY"]
check("LiteLLM master key is generated, not the public default", master.startswith("sk-") and master != "sk-admin123")
check("LiteLLM master key is long", len(master) >= 40)
check("LiteLLM salt is generated and differs from the master key", salt.startswith("sk-") and salt != master)
check("no admin123 anywhere in rendered output", "admin123" not in (tmp / "default.yaml").read_text())

litellm_env = container_env(find(default, "Deployment", "litellm"), "litellm")
check("litellm reads master key from the secret", secret_ref(litellm_env, "LITELLM_MASTER_KEY").get("key") == "LITELLM_MASTER_KEY")
check("litellm reads salt from the secret", secret_ref(litellm_env, "LITELLM_SALT_KEY").get("key") == "LITELLM_SALT_KEY")
agents_env = container_env(find(default, "Deployment", "agents"), "agents")
check("agents reads the same master key", secret_ref(agents_env, "LITELLM_ADMIN_KEY").get("key") == "LITELLM_MASTER_KEY")

explicit = find(docs("explicit.yaml"), "Secret", "nemesis-secrets")["stringData"]
check("explicit adminPassword is used", explicit["LITELLM_MASTER_KEY"] == "sk-custom")
check("explicit saltKey is used", explicit["LITELLM_SALT_KEY"] == "sk-salt")
legacy = find(docs("legacy.yaml"), "Secret", "nemesis-secrets")["stringData"]
check("legacy llm.litellm.env.litellmAdminPassword is honored", legacy["LITELLM_MASTER_KEY"] == "sk-legacy")

# --- NEM-SEC-011: Jupyter and Grafana ---
jupyter_env = container_env(find(default, "Deployment", "jupyter"), "jupyter")
check("jupyter does not receive the Hasura admin secret", "HASURA_ADMIN_SECRET" not in jupyter_env)
check("jupyter still gets the Hasura URL", "HASURA_GRAPHQL_URL" in jupyter_env)
grafana_env = container_env(find(default, "Deployment", "grafana"), "grafana")
check("grafana anonymous users are not Editors", grafana_env["GF_AUTH_ANONYMOUS_ORG_ROLE"]["value"] == "Viewer")

if failures:
    print(f"{failures} check(s) failed")
    sys.exit(1)
print("All checks passed")
EOF
