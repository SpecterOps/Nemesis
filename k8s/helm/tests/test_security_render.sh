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
render "$TMP/hosted.yaml" --set ingress.host=nemesis.example
# Credentials with every character that breaks YAML quoting or URL parsing
render "$TMP/quoted.yaml" --set-string 'credentials.postgres.password=pa"ss w@rd:/#%?&+\\' \
  --set-string 'credentials.rabbitmq.password=r@bbit:/#%"+ x'

python3 - "$TMP" "$(cd "$CHART/../../.." && pwd)" <<'EOF'
import sys
from pathlib import Path

import json
import re
from urllib.parse import unquote, urlsplit

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

# --- NEM-SEC-007: Gotenberg must not reach Dapr/Kubernetes secrets ---
deployments = [d for d in default if d["kind"] == "Deployment"]
dapr_apps = {
    d["spec"]["template"]["metadata"]["annotations"]["dapr.io/app-id"]
    for d in deployments
    if (d["spec"]["template"]["metadata"].get("annotations") or {}).get("dapr.io/enabled") == "true"
}
gotenberg = find(default, "Deployment", "gotenberg")
gt_pod = gotenberg["spec"]["template"]
gt_ann = gt_pod["metadata"]["annotations"]
check("gotenberg sidecar has no secrets volume mount", "dapr.io/volume-mounts" not in gt_ann)
check("gotenberg pod has no dapr-secrets volume", all(v["name"] != "dapr-secrets" for v in gt_pod["spec"].get("volumes", [])))
check("gotenberg uses its own Dapr configuration", gt_ann["dapr.io/config"] == "gotenberg-dapr-config")
check("gotenberg uses its own ServiceAccount", gt_pod["spec"].get("serviceAccountName") == "gotenberg")
check("gotenberg ServiceAccount exists", any(d["kind"] == "ServiceAccount" and d["metadata"]["name"] == "gotenberg" for d in default))
bindings = [d for d in default if d["kind"] in ("RoleBinding", "ClusterRoleBinding")]
check(
    "gotenberg ServiceAccount has no RBAC bindings",
    all(s.get("name") != "gotenberg" for b in bindings for s in b.get("subjects", [])),
)
gt_config = find(default, "Configuration", "gotenberg-dapr-config")
denied = {s["storeName"] for s in gt_config["spec"]["secrets"]["scopes"] if s["defaultAccess"] == "deny"}
check("gotenberg Dapr config denies every secret store", denied == {"nemesis-secret-store", "kubernetes"})

web_ann = find(default, "Deployment", "web-api")["spec"]["template"]["metadata"]["annotations"]
check("other sidecars still mount the secrets file", web_ann.get("dapr.io/volume-mounts") == "dapr-secrets:/dapr/secrets")

for component in ("nemesis-secret-store", "statestore"):
    scopes = set(find(default, "Component", component).get("scopes") or [])
    check(f"{component} is scoped and excludes gotenberg", scopes and "gotenberg" not in scopes)
    check(f"{component} keeps every other Dapr app", scopes == dapr_apps - {"gotenberg"})

# --- /rabbitmq and /llm behind the Nemesis login ---
import base64

routes = find(default, "IngressRoute", "nemesis-ingress")["spec"]["routes"]


def route(match_part):
    return next(r for r in routes if match_part in r["match"])


def mw_names(r):
    return [m["name"] for m in r.get("middlewares", [])]


rmq = route("PathPrefix(`/rabbitmq`)")
check("rabbitmq route needs a login first", mw_names(rmq)[:1] == ["nemesis-rabbitmq-auth"])
rmq_users = find(default, "Secret", "nemesis-rabbitmq-auth-secret")["stringData"]["users"].split()
check("rabbitmq login accepts the Nemesis users", find(default, "Secret", "nemesis-basic-auth-secret")["stringData"]["users"] in rmq_users)
check("rabbitmq login accepts the RabbitMQ account (bcrypt)", any(u.startswith("nemesis:$2a$") for u in rmq_users))
check("rabbitmq route swaps in the RabbitMQ credentials", "nemesis-rabbitmq-credentials" in mw_names(rmq))
creds = find(default, "Middleware", "nemesis-rabbitmq-credentials")["spec"]["headers"]["customRequestHeaders"]
check(
    "credentials middleware carries user:password from values",
    base64.b64decode(creds["Authorization"].removeprefix("Basic ")).decode() == "nemesis:Qwerty12345",
)
public = route("/rabbitmq/api/version")
check("public rabbitmq route covers only version and auth", public["match"].count("Path(") == 2 and "PathPrefix" not in public["match"])
check("public rabbitmq route wins over the prefix route", public["priority"] > rmq["priority"])
check("public rabbitmq route strips credentials", mw_names(public) == ["nemesis-rabbitmq-anonymous"])
anon = find(default, "Middleware", "nemesis-rabbitmq-anonymous")["spec"]["headers"]["customRequestHeaders"]
check("anonymous middleware removes Authorization", anon == {"Authorization": ""})
check("every other route needs the Nemesis login", all("nemesis-basic-auth" in mw_names(r) for r in routes if r not in (public, rmq) and "Sec-Fetch-Site" not in r["match"]))

# --- cross-site (CSRF) block, same rule as Compose ---
compose_rule = " ".join(
    yaml.safe_load(Path(sys.argv[2], "infra/traefik/config/cross-site.yml").read_text())["http"]["routers"]["block-cross-site"]["rule"].split()
)
block = route("Sec-Fetch-Site")
check("cross-site route uses the same rule as Compose", " ".join(block["match"].split()) == compose_rule)
check("cross-site route outranks every other route", block["priority"] > max(r.get("priority", 0) for r in routes if r is not block))
check("cross-site route refuses with the deny middleware", mw_names(block) == ["nemesis-deny-all"])
check("cross-site route avoids cross-provider references", all("@" not in s["name"] for s in block["services"]))
deny = find(default, "Middleware", "nemesis-deny-all")["spec"]
check("deny middleware allows no address", deny == {"ipAllowList": {"sourceRange": ["255.255.255.255/32"]}})
hosted = find(docs("hosted.yaml"), "IngressRoute", "nemesis-ingress")["spec"]["routes"]
hosted_block = next(r for r in hosted if "Sec-Fetch-Site" in r["match"])
check("with ingress.host the rule is grouped after Host()", hosted_block["match"].startswith("Host(`nemesis.example`) && (HeaderRegexp("))

# --- nothing reachable over plain HTTP or outside the cluster except the HTTPS ingress ---
check("no Service is exposed outside the cluster", all(d["spec"].get("type", "ClusterIP") == "ClusterIP" for d in default if d["kind"] == "Service"))
check("IngressRoutes only use the websecure entrypoint", all(d["spec"]["entryPoints"] == ["websecure"] for d in default if d["kind"] == "IngressRoute"))
check("no other ingress kinds", not [d for d in default if d["kind"] in ("Ingress", "IngressRouteTCP", "IngressRouteUDP")])
pod_specs = [d["spec"]["template"]["spec"] for d in default if d["kind"] in ("Deployment", "StatefulSet", "DaemonSet")]
check("no pod uses the host network", not any(ps.get("hostNetwork") for ps in pod_specs))
check(
    "no container binds a host port",
    not any(p.get("hostPort") for ps in pod_specs for c in ps["containers"] for p in c.get("ports", [])),
)
repo = Path(sys.argv[2])
for script in ("setup-cluster-k3d.sh", "setup-cluster-k3s.sh", "setup-cluster-eks.sh"):
    text = (repo / "k8s/scripts" / script).read_text()
    check(f"{script}: Traefik has no plain-HTTP entrypoint", '--set "ports.web=null"' in text)
    check(f"{script}: Traefik dashboard/API disabled", '--set "api.dashboard=false"' in text)
    check(f"{script}: Traefik pinned to v3.7.20", '--set "image.tag=v3.7.20"' in text)
    check(f"{script}: Dapr scheduler serves actor placement", "--set global.scheduler.placement.enabled=true" in text)
    check(f"{script}: Traefik metrics get a ClusterIP Service", '--set "metrics.prometheus.service.enabled=true"' in text)
    check(f"{script}: Traefik metrics port is not exposed on the public Service", "ports.metrics.expose" not in text)

# --- pgbouncer: signed CloudNativePG image, config from files, no root ---
pgb = find(default, "Deployment", "pgbouncer")["spec"]["template"]["spec"]
pgb_c = pgb["containers"][0]
check("pgbouncer uses the CloudNativePG image", pgb_c["image"].startswith("ghcr.io/cloudnative-pg/pgbouncer:1.26.1-"))
check("pgbouncer gets no credentials through env", not pgb_c.get("env"))
check("pgbouncer runs as non-root", pgb["securityContext"]["runAsNonRoot"] is True)
check("pgbouncer root filesystem is read-only", pgb_c["securityContext"]["readOnlyRootFilesystem"] is True)
check("pgbouncer userlist comes from a Secret", any(v.get("secret", {}).get("secretName") == "pgbouncer-userlist" for v in pgb["volumes"]))
ini = find(default, "ConfigMap", "pgbouncer-config")["data"]["pgbouncer.ini"]
check("pgbouncer uses SCRAM", "auth_type = scram-sha-256" in ini)
check("pgbouncer handles asyncpg prepared statements in transaction mode", "max_prepared_statements = 200" in ini)
check("pgbouncer config holds no password", "Qwerty" not in ini and "password" not in ini.lower())
check("other roles resolve through auth_user", "auth_user=" in ini)
quoted = docs("quoted.yaml")
PG_PW = 'pa"ss w@rd:/#%?&+\\'
RMQ_PW = 'r@bbit:/#%"+ x'
check("userlist escapes double quotes", find(quoted, "Secret", "pgbouncer-userlist")["stringData"]["userlist.txt"].strip().endswith('"' + PG_PW.replace('"', '""') + '"'))


def url_password(url):
    return unquote(urlsplit(url).password)


# Every connection URL in the rendered chart decodes back to the real password
urls = []
for d in quoted:
    if d["kind"] == "Secret":
        for k, v in d.get("stringData", {}).items():
            if k == "secrets.json":
                urls += [x for x in json.loads(v).values() if "://" in str(x)]
            elif "://" in str(v):
                urls.append(v)
    if d["kind"] == "ConfigMap":
        for v in d.get("data", {}).values():
            urls += re.findall(r'"((?:postgresql|amqp)://[^"]+)"', v)
    if d["kind"] in ("Deployment", "StatefulSet"):
        for c in d["spec"]["template"]["spec"]["containers"]:
            urls += [e["value"] for e in c.get("env", []) if "://" in str(e.get("value", "")) and "@" in str(e.get("value", ""))]
pg_urls = [u for u in urls if u.startswith("postgresql://")]
amqp_urls = [u for u in urls if u.startswith("amqp://")]
check("found postgres URLs with credentials", len(pg_urls) >= 6)
check("found amqp URLs with credentials", len(amqp_urls) >= 2)
check("every postgres URL decodes to the password", all(url_password(u) == PG_PW for u in pg_urls))
check("every amqp URL decodes to the password", all(url_password(u) == RMQ_PW for u in amqp_urls))
check("no URL is built with $(VAR) expansion", not any("$(" in u for u in urls))

# --- Prometheus pod discovery stays inside the Nemesis namespace ---
prom_pod = find(default, "Deployment", "prometheus")["spec"]["template"]["spec"]
check("prometheus runs as its own ServiceAccount", prom_pod.get("serviceAccountName") == "prometheus")
check("pod discovery uses a namespaced Role, not a ClusterRole", not any(d["kind"] in ("ClusterRole", "ClusterRoleBinding") and "prometheus" in d["metadata"]["name"] for d in default))
check("pod discovery Role only reads pods", find(default, "Role", "prometheus-pod-discovery")["rules"] == [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}])
prom_cfg = yaml.safe_load(find(default, "ConfigMap", "prometheus-config")["data"]["prometheus.yml"])
jobs = {j["job_name"]: j for j in prom_cfg["scrape_configs"]}
check("dapr-sidecars scrape every sidecar pod", jobs["dapr-sidecars"]["kubernetes_sd_configs"][0]["role"] == "pod")
check("pod discovery is limited to the Nemesis namespace", all(len(sd["namespaces"]["names"]) == 1 for j in jobs.values() for sd in j.get("kubernetes_sd_configs", [])))
check("traefik metrics come from kube-system", jobs["traefik"]["static_configs"][0]["targets"] == ["traefik-metrics.kube-system.svc.cluster.local:9100"])

llm = route("PathPrefix(`/llm`)")
check("llm route needs the Nemesis login", "nemesis-basic-auth" in mw_names(llm))
litellm_cfg = yaml.safe_load(find(default, "ConfigMap", "litellm-config")["data"]["config.yml"])
check("litellm reads keys from x-litellm-api-key", litellm_cfg["general_settings"]["litellm_key_header_name"] == "x-litellm-api-key")
check("litellm trusts forwarded proto", litellm_env["FORWARDED_ALLOW_IPS"]["value"] == "*")

if failures:
    print(f"{failures} check(s) failed")
    sys.exit(1)
print("All checks passed")
EOF
