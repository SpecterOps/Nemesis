#!/usr/bin/env bash
# Checks that every Traefik route in compose.yaml sits behind the Nemesis basic auth. Requires python3 with PyYAML.
# Run: ./tools/tests/test_compose_routes.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "$ROOT" <<'PY'
import re
import sys
from pathlib import Path

import yaml

root = Path(sys.argv[1])
compose = yaml.safe_load((root / "compose.yaml").read_text())
failures = 0


def check(desc, cond):
    global failures
    print(("ok   - " if cond else "FAIL - ") + desc)
    failures += 0 if cond else 1


labels = {}
for svc in compose["services"].values():
    for label in svc.get("labels", []):
        key, _, value = label.partition("=")
        labels[key] = value

routers = {m.group(1) for k in labels if (m := re.match(r"traefik\.http\.routers\.([^.]+)\.rule$", k))}
middlewares = {r: labels.get(f"traefik.http.routers.{r}.middlewares", "").split(",") for r in routers}

# Only these two read-only RabbitMQ endpoints may skip the login (the UI loads them before its login form)
PUBLIC = {"rabbitmq-ui-public"}
for router in sorted(routers - PUBLIC):
    check(f"router {router} requires the Nemesis login", "auth" in middlewares[router])

check(
    "public RabbitMQ router matches only api/version and api/auth",
    labels["traefik.http.routers.rabbitmq-ui-public.rule"]
    == "Path(`/rabbitmq/api/version`) || Path(`/rabbitmq/api/auth`)",
)
check("public RabbitMQ router strips credentials", middlewares["rabbitmq-ui-public"] == ["rabbitmq-anonymous@file"])
check(
    "RabbitMQ UI gets the RabbitMQ credentials after the Nemesis login",
    middlewares["rabbitmq-ui"] == ["auth", "rabbitmq-credentials@file"],
)

traefik_file = (root / "infra/traefik/config/rabbitmq.yml").read_text()
dynamic = yaml.safe_load(traefik_file)["http"]["middlewares"]
check(
    "credentials middleware is built from RABBITMQ_USER/RABBITMQ_PASSWORD",
    'env "RABBITMQ_USER"' in traefik_file and 'env "RABBITMQ_PASSWORD"' in traefik_file and "b64enc" in traefik_file,
)
check("anonymous middleware removes Authorization", dynamic["rabbitmq-anonymous"]["headers"]["customRequestHeaders"] == {"Authorization": ""})
traefik_env = compose["services"]["traefik"]["environment"]
check("Traefik receives the RabbitMQ credentials", any(e.startswith("RABBITMQ_USER=") for e in traefik_env) and any(e.startswith("RABBITMQ_PASSWORD=") for e in traefik_env))

litellm = compose["services"]["litellm"]
check("LiteLLM healthcheck uses the x-litellm-api-key header", "'x-litellm-api-key'" in " ".join(litellm["healthcheck"]["test"]))
check("LiteLLM trusts Traefik's forwarded proto", "FORWARDED_ALLOW_IPS=*" in litellm["environment"])
litellm_cfg = yaml.safe_load((root / "infra/litellm/config.yml").read_text())
check("LiteLLM reads keys from x-litellm-api-key", litellm_cfg["general_settings"]["litellm_key_header_name"] == "x-litellm-api-key")

if failures:
    print(f"{failures} check(s) failed")
    sys.exit(1)
print("All checks passed")
PY
