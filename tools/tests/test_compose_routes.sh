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
    check(f"router {router} requires a login", middlewares[router][:1] == (["rabbitmq-auth@file"] if router == "rabbitmq-ui" else ["auth@file"]))

check(
    "public RabbitMQ router matches only api/version and api/auth",
    labels["traefik.http.routers.rabbitmq-ui-public.rule"]
    == "Path(`/rabbitmq/api/version`) || Path(`/rabbitmq/api/auth`)",
)
check("public RabbitMQ router strips credentials", middlewares["rabbitmq-ui-public"] == ["rabbitmq-anonymous@file"])
check(
    "RabbitMQ UI gets the RabbitMQ credentials after the Nemesis login",
    middlewares["rabbitmq-ui"] == ["rabbitmq-auth@file", "rabbitmq-credentials@file"],
)

traefik_file = (root / "infra/traefik/config/rabbitmq.yml").read_text()
# Drop the Go-template lines (users list) so the rest parses as plain YAML
plain = "\n".join(line for line in traefik_file.splitlines() if "{{" not in line)
dynamic = yaml.safe_load(plain)["http"]["middlewares"]
check(
    "credentials middleware is built from RABBITMQ_USER/RABBITMQ_PASSWORD",
    'env "RABBITMQ_USER"' in traefik_file and 'env "RABBITMQ_PASSWORD"' in traefik_file and "b64enc" in traefik_file,
)
check("anonymous middleware removes Authorization", dynamic["rabbitmq-anonymous"]["headers"]["customRequestHeaders"] == {"Authorization": ""})
# Cross-site (CSRF) block: checked before every other router, refuses with 403
cross = yaml.safe_load((root / "infra/traefik/config/cross-site.yml").read_text())["http"]
block = cross["routers"]["block-cross-site"]
other_priorities = [int(v) for k, v in labels.items() if k.endswith(".priority")]
check("cross-site router outranks every compose router", block["priority"] > max(other_priorities + [0]))
check("cross-site router is on the websecure entrypoint", block["entryPoints"] == ["websecure"])
check("cross-site router matches Sec-Fetch-Site cross-site/same-site", "cross-site|same-site" in block["rule"])
check("cross-site router matches Origin null", "HeaderRegexp(`Origin`" in block["rule"])
check("cross-site router uses the deny middleware", block["middlewares"] == ["deny-all"] and block["service"] == "noop@internal")
check("deny middleware allows no address", cross["middlewares"]["deny-all"]["ipAllowList"]["sourceRange"] == ["255.255.255.255/32"])
check(
    "RabbitMQ route accepts the Nemesis users and the RabbitMQ account",
    'env "BASIC_AUTH_USERS"' in traefik_file and 'htpasswd (env "RABBITMQ_USER") (env "RABBITMQ_PASSWORD")' in traefik_file,
)
traefik_env = compose["services"]["traefik"]["environment"]

# --- nothing reachable over plain HTTP, and no unauthenticated Traefik routers or API ---
traefik = compose["services"]["traefik"]
cmd = traefik["command"]
check("Traefik publishes only the HTTPS entrypoint", traefik["ports"] == ["${NEMESIS_PORT:-7443}:443"])
check("no plain-HTTP web entrypoint", not any(c.startswith("--entrypoints.web.") for c in cmd))
check("Traefik API/dashboard is not served", not any(c.startswith("--api") for c in cmd))
check("metrics use their own internal entrypoint", "--metrics.prometheus.entrypoint=metrics" in cmd)
check("Traefik container gets no Docker router of its own", not traefik.get("labels"))
check(
    "Docker provider only routes this Compose project",
    "--providers.docker.constraints=Label(`com.docker.compose.project`,`nemesis`)" in cmd and compose["name"] == "nemesis",
)
for name, svc in compose["services"].items():
    if name == "traefik":
        continue
    published = [str(p) for p in svc.get("ports", [])]
    check(f"{name} publishes no port on all interfaces", all(p.startswith("127.0.0.1:") for p in published))
jupyter_config = (root / "projects/jupyter/jupyter_config.py").read_text()
check("Jupyter keeps its XSRF check", "disable_check_xsrf" not in jupyter_config)
check("Jupyter does not allow every origin", "allow_origin" not in jupyter_config)
auth_file = (root / "infra/traefik/config/auth.yml").read_text()
check("login middleware is built from BASIC_AUTH_USERS", 'env "BASIC_AUTH_USERS"' in auth_file and "basicAuth" in auth_file)
check("Traefik receives BASIC_AUTH_USERS", any(e.startswith("BASIC_AUTH_USERS=") for e in traefik["environment"]))
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
