# Kubernetes Deployment (k3d)

Deploy Nemesis to a lightweight Kubernetes cluster using [k3d](https://k3d.io/) (k3s-in-Docker), with Dapr operator-managed sidecars and KEDA event-driven autoscaling.

!!! note
    Docker Compose remains the primary development environment. Kubernetes deployment is additive and intended for production-like environments and autoscaling testing. See the [quickstart guide](quickstart.md) for Docker Compose setup.

## Prerequisites

| Tool | Install |
|------|---------|
| [k3d](https://k3d.io/) | `curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh \| bash` |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | See docs |
| [Helm](https://helm.sh/) | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |
| Docker | Must be running |

Dapr and KEDA are installed automatically via Helm by the setup script.

**System requirements** are the same as Docker Compose (4 cores, 12+ GB RAM, 100 GB disk).

## Quick Start

```bash
# 1. Create cluster with Traefik, Dapr, and KEDA
./k8s/scripts/setup-cluster.sh

# 2. Deploy using pre-built images from ghcr.io
./k8s/scripts/deploy.sh install

# 3. Verify everything is running
./k8s/scripts/verify.sh

# Access Nemesis at https://localhost:7443 (default user: n / password: n)
```

## Building Locally

To build and deploy from source using the k3d local registry:

```bash
# Build all images and push to k3d registry
./k8s/scripts/build-and-push.sh

# Deploy using local images
./k8s/scripts/deploy.sh install --build

# Or build specific services only
./k8s/scripts/build-and-push.sh web-api frontend
```

## Deploy Script

```
./k8s/scripts/deploy.sh <action> [options]

Actions:
  install       Install or upgrade Nemesis
  uninstall     Remove Nemesis
  status        Show deployment status

Options:
  --build        Build images locally before deploying
  --monitoring   Enable monitoring (deferred)
  --dry-run      Render templates without deploying
  --values FILE  Additional Helm values file
  --set KEY=VAL  Override a specific value
```

### Examples

```bash
# Deploy with ghcr.io images
./k8s/scripts/deploy.sh install

# Deploy with locally built images
./k8s/scripts/deploy.sh install --build

# Override credentials
./k8s/scripts/deploy.sh install \
  --set credentials.postgres.password=StrongPass \
  --set credentials.rabbitmq.password=StrongPass \
  --set credentials.minio.password=StrongPass

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
| Service discovery | Docker DNS | K8s Service DNS |

### What the Setup Script Installs

The `setup-cluster.sh` script creates a k3d cluster and installs:

- **Traefik** (Helm chart v34.3.0) — reverse proxy with TLS termination
- **Dapr** (Helm chart v1.16.9) — sidecar injection, pub/sub, workflows, secrets
- **KEDA** (Helm chart v2.16.1) — event-driven autoscaling from RabbitMQ queue depth

All versions are pinned for reproducibility.

### KEDA Autoscaling

KEDA monitors RabbitMQ queue depth and scales these services automatically:

| Service | Queue | Threshold | Min | Max | Cooldown |
|---------|-------|-----------|-----|-----|----------|
| file-enrichment | `files-new_file` | 10 messages | 1 | 5 | 300s |
| document-conversion | `files-document_conversion_input` | 5 messages | 1 | 5 | 300s |

All thresholds are configurable in `values.yaml` under `autoscaling`.

!!! tip
    Queue names are created by Dapr as `{consumerID}-{topic}`. Verify actual queue names in the RabbitMQ management UI after first deployment and update `values.yaml` if they differ.

### Helm Chart Structure

```
k8s/helm/nemesis/
├── Chart.yaml
├── values.yaml              # All configuration
├── values-dev.yaml          # Local registry overrides
├── files/                   # Static files (SQL, configs)
└── templates/
    ├── _helpers.tpl
    ├── namespace.yaml
    ├── secrets.yaml
    ├── configmap-*.yaml
    ├── dapr/                # Dapr CRDs (secretstore, statestore, pubsub, configs)
    ├── infra/               # PostgreSQL, RabbitMQ, MinIO, Hasura
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

### Teardown

```bash
# Delete cluster (preserves registry for faster rebuilds)
./k8s/scripts/teardown-cluster.sh

# Delete cluster AND registry
./k8s/scripts/teardown-cluster.sh --registry
```

## Configuration

All configuration is in `k8s/helm/nemesis/values.yaml`. Key sections:

| Section | Description |
|---------|-------------|
| `credentials.*` | PostgreSQL, RabbitMQ, MinIO, Hasura passwords |
| `nemesis.*` | URL, log level, expiration defaults |
| `autoscaling.*` | KEDA scaling thresholds and limits |
| `fileEnrichment.*` | File enrichment replicas, resources, env vars |
| `postgres.*` | Database image, storage, max connections |
| `rabbitmq.*` | Message queue image, storage |
| `minio.*` | Object storage image, buckets, storage |

### PostgreSQL Connection Tuning

The default `max_connections` is set to 300 to accommodate autoscaling. Connection pools are configurable per service via environment variables:

- `DB_POOL_MAX_SIZE` (default: 20) — maximum connections per pod
- `DB_POOL_MIN_SIZE` (default: 2) — minimum idle connections per pod

With KEDA scaling file-enrichment to 5 replicas, this means 5 x 20 = 100 application connections at peak, well within the 300 limit.

## Deferred Features

The following will be added in future updates:

- **Monitoring stack** (Grafana, Prometheus, Jaeger, Loki) — toggle: `monitoring.enabled`
- **LLM stack** (LiteLLM, Phoenix, Agents) — toggle: `llm.enabled`
- **Jupyter** — toggle: `jupyter.enabled`

The `values.yaml` toggles exist but no templates are generated yet.

## Troubleshooting

### Pods stuck in `CrashLoopBackOff`

Check infrastructure first — app pods depend on PostgreSQL, RabbitMQ, and MinIO:
```bash
kubectl logs deployment/postgres -n nemesis
kubectl logs statefulset/rabbitmq -n nemesis
kubectl logs statefulset/minio -n nemesis
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
Update `autoscaling.fileEnrichment.queueName` / `autoscaling.documentConversion.queueName` in `values.yaml` if names differ.

### Connection pool exhaustion

If you see `FATAL: sorry, too many clients already` in PostgreSQL logs:

1. Check current connections: `kubectl exec deployment/postgres -n nemesis -- psql -U nemesis -d enrichment -c "SELECT count(*) FROM pg_stat_activity;"`
2. Check pool stats: port-forward to file-enrichment and hit `/system/pool-stats`
3. Reduce per-pod pool size via `DB_POOL_MAX_SIZE` env var, or increase `postgres.maxConnections` in `values.yaml`
