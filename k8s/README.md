# Nemesis on Kubernetes

Deploy Nemesis to a lightweight Kubernetes cluster using either [k3d](https://k3d.io/) (k3s-in-Docker) or native [k3s](https://k3s.io/), with Dapr operator-managed sidecars and KEDA event-driven autoscaling.

> **Note:** Docker Compose remains the primary development environment. Kubernetes deployment is additive and intended for production-like environments and autoscaling testing.

## Quick Start (k3d)

k3d runs k3s inside Docker containers — ideal for local development and testing.

### Prerequisites

| Tool | Install |
|------|---------|
| [k3d](https://k3d.io/) | `curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh \| bash` |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | See docs |
| [Helm](https://helm.sh/) | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |
| Docker | Must be running |

### Setup

```bash
# 1. Create cluster with Dapr + KEDA
./k8s/scripts/setup-cluster-k3d.sh

# 2. Deploy using pre-built images from ghcr.io
./k8s/scripts/deploy.sh install

# 3. Verify everything is running
./k8s/scripts/verify.sh

# Access Nemesis at https://localhost:7443 (default user: n / password: n)
```

### Teardown

```bash
# Delete cluster (preserves registry for rebuilds)
./k8s/scripts/teardown-cluster-k3d.sh

# Delete cluster AND registry
./k8s/scripts/teardown-cluster-k3d.sh --registry
```

## Quick Start (k3s)

k3s runs natively on the host — suited for VMs, bare-metal servers, and production-like environments where Docker is not available or desired.

### Prerequisites

| Tool | Install |
|------|---------|
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | See docs |
| [Helm](https://helm.sh/) | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |
| curl | System package manager |

> **Note:** Docker is **not** required. k3s uses containerd directly.

### Setup

```bash
# 1. Install k3s and configure Traefik, Dapr, KEDA
./k8s/scripts/setup-cluster-k3s.sh

# 2. Deploy using pre-built images from ghcr.io
./k8s/scripts/deploy.sh install

# 3. Verify everything is running
./k8s/scripts/verify.sh

# Access Nemesis at https://localhost:7443 (default user: n / password: n)
```

### Teardown

```bash
# Remove everything including k3s
./k8s/scripts/teardown-cluster-k3s.sh

# Remove only Nemesis and Helm releases, keep k3s running
./k8s/scripts/teardown-cluster-k3s.sh --keep-k3s
```

## Building Locally

The `--build` flag auto-detects the cluster type and uses the appropriate method:

- **k3d**: Builds images and pushes to the k3d local registry
- **k3s**: Builds images and loads them into k3s containerd via `k3s ctr images import`

Both require Docker to build images.

```bash
# Deploy using locally built images (auto-detects k3d or k3s)
./k8s/scripts/deploy.sh install --build

# Or build images separately:
./k8s/scripts/build-and-push-k3d.sh           # k3d: push to local registry
./k8s/scripts/build-and-load-k3s.sh           # k3s: load into containerd

# Build specific services only
./k8s/scripts/build-and-push-k3d.sh web-api frontend
./k8s/scripts/build-and-load-k3s.sh web-api frontend
```

## Deploy Script Usage

```bash
./k8s/scripts/deploy.sh <action> [options]

# Actions:
#   install       Install or upgrade Nemesis
#   uninstall     Remove Nemesis
#   status        Show deployment status

# Options:
#   --build        Build images locally before deploying (k3d or k3s)
#   --monitoring   Enable monitoring stack
#   --jupyter      Enable Jupyter stack
#   --llm          Enable LLM stack
#   --dry-run      Render templates without deploying
#   --values FILE  Additional Helm values file
#   --set KEY=VAL  Override a specific value

# Examples:
./k8s/scripts/deploy.sh install                              # ghcr.io images
./k8s/scripts/deploy.sh install --build                      # local build (k3d or k3s)
./k8s/scripts/deploy.sh install --set credentials.postgres.password=MySecret
./k8s/scripts/deploy.sh install --dry-run                    # preview only
./k8s/scripts/deploy.sh uninstall                            # remove
./k8s/scripts/deploy.sh status                               # check status
```

## Architecture

### Key Differences from Docker Compose

| Aspect | Docker Compose | Kubernetes |
|--------|---------------|------------|
| Dapr sidecars | Manual `-dapr` containers | Operator-injected via pod annotations |
| Dapr control plane | Standalone placement + scheduler | K8s Dapr installation manages these |
| Secrets | `.env` file + `secretstores.local.env` | K8s Secrets + `secretstores.kubernetes` |
| Reverse proxy | Traefik container with Docker provider | Traefik with IngressRoute CRDs |
| Autoscaling | Manual `docker compose up --scale` | KEDA ScaledObjects on RabbitMQ queue depth |
| Connection pooling | Per-service pools only | PgBouncer (transaction mode) between services and PostgreSQL |
| Service discovery | Docker DNS | K8s Service DNS |

### k3d vs k3s

| Aspect | k3d | k3s |
|--------|-----|-----|
| Runtime | k3s inside Docker containers | Native on host |
| Docker required | Yes | No (uses containerd) |
| Local image builds | Via k3d local registry | Via `k3s ctr images import` |
| Traefik service type | NodePort (mapped via k3d port) | LoadBalancer (built-in ServiceLB/Klipper) |
| Default HTTPS port | 7443 | 7443 |
| Best for | Local dev, CI | VMs, bare-metal, production-like |

### KEDA Autoscaling

KEDA monitors RabbitMQ queue depth and CPU utilization to scale services:

| Service | Trigger | Threshold | Min | Max | Cooldown |
|---------|---------|-----------|-----|-----|----------|
| file-enrichment | Queue: `files-new_file` | 10 messages | 1 | 5 | 60s |
| document-conversion | Queue: `files-document_conversion_input` | 5 messages | 1 | 5 | 60s |
| titus-scanner | Queue: `titus-titus_input` | 10 messages | 1 | 5 | 60s |
| dotnet-service | Queue: `dotnet-dotnet_input` | 5 messages | 1 | 3 | 60s |
| gotenberg | CPU utilization | 70% | 1 | 3 | 120s |

All thresholds are configurable in `values.yaml` under `autoscaling`.

> **Note:** Queue names are created by Dapr as `{consumerID}-{topic}`. The default values assume standard Dapr queue naming. Verify actual queue names in RabbitMQ management UI after first deployment and update `values.yaml` if different. Gotenberg uses CPU-based scaling (not queue-based) since it receives synchronous HTTP requests rather than consuming from a queue.

### PgBouncer Connection Pooling

PgBouncer sits between all services (including Dapr sidecars) and PostgreSQL, multiplexing hundreds of client connections onto a small pool of real database connections. This prevents connection exhaustion during KEDA autoscaling when many pod replicas open connections simultaneously.

- **Pool mode:** transaction — connections are returned to the pool after each transaction
- **Max client connections:** 2000 (configurable in `values.yaml`)
- **Default pool size:** 60 real PostgreSQL connections

All services connect to `pgbouncer:5432` instead of `postgres:5432`. The `postgres` service remains unchanged and is only accessed by PgBouncer directly.

### Helm Chart Structure

```
k8s/helm/nemesis/
├── Chart.yaml
├── values.yaml              # All configuration
├── values-dev.yaml           # Local registry overrides (k3d)
├── values-dev-k3s.yaml       # Local image overrides (k3s)
├── files/                   # Static files (SQL, configs)
└── templates/
    ├── _helpers.tpl
    ├── namespace.yaml
    ├── secrets.yaml
    ├── configmap-*.yaml
    ├── dapr/                # Dapr CRDs (secretstore, statestore, pubsub, configs)
    ├── infra/               # PostgreSQL, RabbitMQ, SeaweedFS, Hasura
    ├── apps/                # Application deployments + services
    ├── ingress/             # Traefik IngressRoute + middleware
    ├── keda/                # KEDA ScaledObjects + TriggerAuthentication
    ├── monitoring/          # Prometheus, Grafana, Loki, Jaeger, etc. (optional)
    ├── jupyter/             # Jupyter notebook (optional)
    ├── llm/                 # LiteLLM, Phoenix, Agents (optional)
    └── tests/               # Helm test pod
```

## Operations

### Check Status

```bash
kubectl get pods -n nemesis
kubectl get svc -n nemesis
kubectl get components.dapr.io -n nemesis
kubectl get scaledobject -n nemesis
```

### View Logs

```bash
kubectl logs -f deployment/web-api -n nemesis
kubectl logs -f deployment/file-enrichment -n nemesis
kubectl logs -f deployment/file-enrichment -c daprd -n nemesis  # Dapr sidecar
```

### Run Helm Tests

```bash
helm test nemesis -n nemesis
```

### Override Values

```bash
# Change credentials
./k8s/scripts/deploy.sh install \
  --set credentials.postgres.password=StrongPass \
  --set credentials.rabbitmq.password=StrongPass \
  --set credentials.s3.secretKey=StrongPass

# Disable autoscaling
./k8s/scripts/deploy.sh install --set autoscaling.enabled=false

# Custom values file
./k8s/scripts/deploy.sh install --values my-values.yaml
```

## Optional Stacks

Enable optional stacks with deploy flags:

```bash
# Enable monitoring (Prometheus, Grafana, Loki, Jaeger, OTEL Collector, etc.)
./k8s/scripts/deploy.sh install --monitoring

# Enable Jupyter notebooks
./k8s/scripts/deploy.sh install --jupyter

# Enable LLM stack (LiteLLM, Phoenix, Agents)
./k8s/scripts/deploy.sh install --llm

# Enable everything
./k8s/scripts/deploy.sh install --monitoring --jupyter --llm
```

When monitoring is enabled, dashboards are available at:
- `/grafana` — Grafana dashboards (Traefik, SeaweedFS, Node Exporter)
- `/prometheus` — Prometheus metrics
- `/jaeger` — Jaeger distributed tracing

When LLM is enabled:
- `/llm` — LiteLLM proxy admin UI
- `/phoenix` — Phoenix LLM observability
- `/mcp` — Agents MCP endpoint

When Jupyter is enabled:
- `/jupyter` — Jupyter notebooks

## Troubleshooting

### Pods stuck in `CrashLoopBackOff`
Check if infrastructure is ready first — app pods depend on PostgreSQL, RabbitMQ, and SeaweedFS:
```bash
kubectl logs deployment/postgres -n nemesis
kubectl logs deployment/rabbitmq -n nemesis
```

### Dapr sidecar not injecting
Verify the namespace label: `kubectl get ns nemesis --show-labels`
Should include `dapr.io/inject=true`.

### KEDA not scaling
Verify queue names match what Dapr created:
```bash
kubectl port-forward svc/rabbitmq 15672:15672 -n nemesis
# Open http://localhost:15672 and check queue names
```
Update queue names in the `autoscaling.*` section of values.yaml if names differ.
