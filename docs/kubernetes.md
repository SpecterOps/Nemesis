# Kubernetes Deployment

Deploy Nemesis to a lightweight Kubernetes cluster using either [k3d](https://k3d.io/) (k3s-in-Docker) or native [k3s](https://k3s.io/), with Dapr operator-managed sidecars and KEDA event-driven autoscaling.

!!! note
    Docker Compose remains the primary development environment. Kubernetes deployment is additive and intended for production-like environments and autoscaling testing. See the [quickstart guide](quickstart.md) for Docker Compose setup.

**System requirements** are the same as Docker Compose (4 cores, 12+ GB RAM, 100 GB disk).

## Quick Start (k3d)

k3d runs k3s inside Docker containers — ideal for local development and testing.

### Prerequisites

| Tool | Install |
|------|---------|
| [k3d](https://k3d.io/) | `curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh \| bash` |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | See docs |
| [Helm](https://helm.sh/) | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |
| Docker | Must be running |

Dapr and KEDA are installed automatically via Helm by the setup script.

### Setup

```bash
# 1. Create cluster with Traefik, Dapr, and KEDA
./k8s/scripts/setup-cluster-k3d.sh

# 2. Deploy using pre-built images from ghcr.io
./k8s/scripts/deploy.sh install

# 3. Verify everything is running
./k8s/scripts/verify.sh

# Access Nemesis at https://localhost:7443 (default user: n / password: n)
```

### Teardown

```bash
# Delete cluster (preserves registry for faster rebuilds)
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

Docker is **not** required. k3s uses containerd directly.

Dapr and KEDA are installed automatically via Helm by the setup script.

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

!!! note
    k3s `--build` requires Docker on the same host to build images. The images are exported via `docker save` and imported into k3s containerd. The pods use `imagePullPolicy: Never` to ensure they use the locally-loaded images.

## Deploy Script

```
./k8s/scripts/deploy.sh <action> [options]

Actions:
  install       Install or upgrade Nemesis
  uninstall     Remove Nemesis
  status        Show deployment status

Options:
  --build        Build images locally before deploying (k3d or k3s)
  --monitoring   Enable monitoring (deferred)
  --dry-run      Render templates without deploying
  --values FILE  Additional Helm values file
  --set KEY=VAL  Override a specific value
```

### Examples

```bash
# Deploy with ghcr.io images
./k8s/scripts/deploy.sh install

# Deploy with locally built images (k3d or k3s)
./k8s/scripts/deploy.sh install --build

# Override credentials
./k8s/scripts/deploy.sh install \
  --set credentials.postgres.password=StrongPass \
  --set credentials.rabbitmq.password=StrongPass \
  --set credentials.s3.secretKey=StrongPass

# Disable autoscaling
./k8s/scripts/deploy.sh install --set autoscaling.enabled=false

# Preview rendered templates
./k8s/scripts/deploy.sh install --dry-run

# Custom values file
./k8s/scripts/deploy.sh install --values my-values.yaml
```

## Architecture

### Key Differences from Docker Compose

| Aspect | Docker Compose | Kubernetes |
|--------|---------------|------------|
| Dapr sidecars | Manual `-dapr` containers | Operator-injected via pod annotations |
| Dapr control plane | Standalone placement + scheduler | Helm-installed Dapr operator |
| Secrets | `.env` file + `secretstores.local.env` | K8s Secrets + `secretstores.kubernetes` |
| Reverse proxy | Traefik container with Docker provider | Traefik with IngressRoute CRDs |
| Autoscaling | Manual `docker compose up --scale` | KEDA ScaledObjects on RabbitMQ queue depth |
| Connection pooling | Per-service pools only | PgBouncer (transaction mode) between services and PostgreSQL |
| Service discovery | Docker DNS | K8s Service DNS |

### What the Setup Scripts Install

Both `setup-cluster-k3d.sh` and `setup-cluster-k3s.sh` install the same Helm components:

- **Traefik** (Helm chart v34.3.0) — reverse proxy with TLS termination
- **Dapr** (Helm chart v1.16.9) — sidecar injection, pub/sub, workflows, secrets
- **KEDA** (Helm chart v2.16.1) — event-driven autoscaling from RabbitMQ queue depth

All versions are pinned for reproducibility.

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

KEDA monitors RabbitMQ queue depth and CPU utilization to scale services automatically:

| Service | Trigger | Threshold | Min | Max | Cooldown |
|---------|---------|-----------|-----|-----|----------|
| file-enrichment | Queue: `files-new_file` | 10 messages | 1 | 5 | 60s |
| document-conversion | Queue: `files-document_conversion_input` | 5 messages | 1 | 5 | 60s |
| titus-scanner | Queue: `titus-titus_input` | 10 messages | 1 | 5 | 60s |
| dotnet-service | Queue: `dotnet-dotnet_input` | 5 messages | 1 | 3 | 60s |
| gotenberg | CPU utilization | 70% | 1 | 3 | 120s |

All thresholds are configurable in `values.yaml` under `autoscaling`.

!!! tip
    Queue names are created by Dapr as `{consumerID}-{topic}`. Verify actual queue names in the RabbitMQ management UI after first deployment and update `values.yaml` if they differ. Gotenberg uses CPU-based scaling (not queue-based) since it receives synchronous HTTP requests rather than consuming from a queue.

### PgBouncer Connection Pooling

PgBouncer sits between all services (including Dapr sidecars) and PostgreSQL, multiplexing hundreds of client connections onto a small pool of real database connections. This prevents connection exhaustion during KEDA autoscaling when many pod replicas open connections simultaneously.

- **Pool mode:** transaction — connections are returned to the pool after each transaction
- **Max client connections:** 500 (configurable in `values.yaml`)
- **Default pool size:** 20 real PostgreSQL connections

All services connect to `pgbouncer:5432` instead of `postgres:5432`. The `postgres` service remains unchanged and is only accessed by PgBouncer directly.

### Helm Chart Structure

```
k8s/helm/nemesis/
├── Chart.yaml
├── values.yaml              # All configuration
├── values-dev.yaml          # Local registry overrides (k3d)
├── values-dev-k3s.yaml      # Local image overrides (k3s)
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
    └── tests/               # Helm test pod
```

## Operations

### Check Status

```bash
kubectl get pods -n nemesis
kubectl get svc -n nemesis
kubectl get components.dapr.io -n nemesis
kubectl get scaledobject -n nemesis

# Or use the deploy script
./k8s/scripts/deploy.sh status
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

## Configuration

All configuration is in `k8s/helm/nemesis/values.yaml`. Key sections:

| Section | Description |
|---------|-------------|
| `credentials.*` | PostgreSQL, RabbitMQ, S3 (SeaweedFS), Hasura passwords |
| `nemesis.*` | URL, log level, expiration defaults |
| `autoscaling.*` | KEDA scaling thresholds and limits |
| `fileEnrichment.*` | File enrichment replicas, resources, env vars |
| `postgres.*` | Database image, storage, max connections |
| `pgbouncer.*` | Connection pooling image, pool size, max client connections |
| `rabbitmq.*` | Message queue image, storage |
| `seaweedfs.*` | Object storage (SeaweedFS) image, buckets, storage |

### PostgreSQL Connection Tuning

All services connect through **PgBouncer** in transaction pooling mode, which multiplexes many client connections onto a small pool of real PostgreSQL connections. This prevents connection exhaustion during autoscaling.

Key settings (configurable in `values.yaml` under `pgbouncer`):

| Setting | Default | Description |
|---------|---------|-------------|
| `maxClientConn` | 2000 | Max simultaneous client connections PgBouncer accepts |
| `defaultPoolSize` | 60 | Real PostgreSQL connections per database |
| `minPoolSize` | 20 | Minimum idle PostgreSQL connections maintained |
| `reservePoolSize` | 15 | Extra connections when pool is exhausted |
| `poolMode` | transaction | Return connections to pool after each transaction |

Per-service pool settings are still configurable via environment variables:

- `DB_POOL_MAX_SIZE` (default: 20) — maximum connections per pod (to PgBouncer)
- `DB_POOL_MIN_SIZE` (default: 2) — minimum idle connections per pod (to PgBouncer)

With KEDA scaling to 5+ replicas across multiple services, PgBouncer keeps real PostgreSQL connections at ~60-75, well within the 300 `max_connections` limit.

## Deferred Features

The following will be added in future updates:

- **Monitoring stack** (Grafana, Prometheus, Jaeger, Loki) — toggle: `monitoring.enabled`
- **LLM stack** (LiteLLM, Phoenix, Agents) — toggle: `llm.enabled`
- **Jupyter** — toggle: `jupyter.enabled`

The `values.yaml` toggles exist but no templates are generated yet.

## Troubleshooting

### Pods stuck in `CrashLoopBackOff`

Check infrastructure first — app pods depend on PostgreSQL, RabbitMQ, and SeaweedFS:
```bash
kubectl logs deployment/postgres -n nemesis
kubectl logs statefulset/rabbitmq -n nemesis
kubectl logs statefulset/seaweedfs -n nemesis
```

### Dapr sidecar not injecting

Verify the namespace label:
```bash
kubectl get ns nemesis --show-labels
```
Should include `dapr.io/inject=true`.

### KEDA not scaling

Verify queue names match what Dapr created:
```bash
kubectl port-forward svc/rabbitmq 15672:15672 -n nemesis
# Open http://localhost:15672 and check queue names
```
Update queue names in the `autoscaling.*` section of `values.yaml` if names differ.

### Connection pool exhaustion

If you see `FATAL: sorry, too many clients already` in PostgreSQL logs:

1. Check PgBouncer stats: `kubectl exec deployment/pgbouncer -n nemesis -- env PGPASSWORD=Qwerty12345 psql -U nemesis -h 127.0.0.1 -p 5432 pgbouncer -c "SHOW POOLS;"`
2. Check PostgreSQL connections: `kubectl exec deployment/postgres -n nemesis -- psql -U nemesis -d enrichment -c "SELECT count(*) FROM pg_stat_activity;"`
3. Check per-service pool stats: port-forward to file-enrichment and hit `/system/pool-stats`
4. Tune PgBouncer: increase `pgbouncer.defaultPoolSize` in `values.yaml` (adds more real PostgreSQL connections)
5. Tune per-pod pools: reduce `DB_POOL_MAX_SIZE` env var to lower client connections to PgBouncer
