# Nemesis on Kubernetes (k3d)

Deploy Nemesis to a lightweight Kubernetes cluster using [k3d](https://k3d.io/) (k3s-in-Docker), with Dapr operator-managed sidecars and KEDA event-driven autoscaling.

> **Note:** Docker Compose remains the primary development environment. Kubernetes deployment is additive and intended for production-like environments and autoscaling testing.

## Prerequisites

Install the following tools:

| Tool | Install |
|------|---------|
| [k3d](https://k3d.io/) | `curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh \| bash` |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | See docs |
| [Helm](https://helm.sh/) | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |
| Docker | Must be running |

> **Note:** Dapr and KEDA are installed automatically via Helm by the setup script — no separate CLI tools are needed.

## Quick Start

```bash
# 1. Create cluster with Dapr + KEDA
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

## Deploy Script Usage

```bash
./k8s/scripts/deploy.sh <action> [options]

# Actions:
#   install       Install or upgrade Nemesis
#   uninstall     Remove Nemesis
#   status        Show deployment status

# Options:
#   --build        Build images locally before deploying
#   --monitoring   Enable monitoring (deferred — flag only)
#   --dry-run      Render templates without deploying
#   --values FILE  Additional Helm values file
#   --set KEY=VAL  Override a specific value

# Examples:
./k8s/scripts/deploy.sh install                              # ghcr.io images
./k8s/scripts/deploy.sh install --build                      # local build
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
| Service discovery | Docker DNS | K8s Service DNS |

### KEDA Autoscaling

KEDA monitors RabbitMQ queue depth and scales these services:

| Service | Queue | Threshold | Min | Max | Cooldown |
|---------|-------|-----------|-----|-----|----------|
| file-enrichment | `files-new_file` | 10 messages | 1 | 5 | 300s |
| document-conversion | `files-document_conversion_input` | 5 messages | 1 | 5 | 300s |
| titus-scanner | `titus-titus_input` | 10 messages | 1 | 5 | 300s |
| dotnet-service | `dotnet-dotnet_input` | 5 messages | 1 | 3 | 300s |

All thresholds are configurable in `values.yaml` under `autoscaling`.

> **Note:** Queue names are created by Dapr as `{consumerID}-{topic}`. The default values assume standard Dapr queue naming. Verify actual queue names in RabbitMQ management UI after first deployment and update `values.yaml` if different.

### Helm Chart Structure

```
k8s/helm/nemesis/
├── Chart.yaml
├── values.yaml              # All configuration
├── values-dev.yaml           # Local registry overrides
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
  --set credentials.minio.password=StrongPass

# Disable autoscaling
./k8s/scripts/deploy.sh install --set autoscaling.enabled=false

# Custom values file
./k8s/scripts/deploy.sh install --values my-values.yaml
```

### Teardown

```bash
# Delete cluster (preserves registry for rebuilds)
./k8s/scripts/teardown-cluster.sh

# Delete cluster AND registry
./k8s/scripts/teardown-cluster.sh --registry
```

## Deferred Features

The following will be added in future updates:
- **Monitoring stack** (Grafana, Prometheus, Jaeger, Loki) — toggle: `monitoring.enabled`
- **LLM stack** (LiteLLM, Phoenix, Agents) — toggle: `llm.enabled`
- **Jupyter** — toggle: `jupyter.enabled`

The `values.yaml` toggles exist but no templates are generated yet.

## Troubleshooting

### Pods stuck in `CrashLoopBackOff`
Check if infrastructure is ready first — app pods depend on PostgreSQL, RabbitMQ, and MinIO:
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
