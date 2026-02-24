# Nemesis Project Context (Codex)

## Security Guardrail

Never read any `.env*` files in this repository.

Blocked examples:
- `.env`
- `.env.local`
- `.env.development`
- `.env.production`
- any path matching `.env*`

If environment variable details are needed, use `env.example`.

## Overview

Nemesis is an open-source centralized data processing platform that ingests, enriches, and enables collaborative analysis of offensive security assessment artifacts.

## Common Commands

### Running Nemesis

```bash
./tools/nemesis-ctl.sh start prod
./tools/nemesis-ctl.sh start prod --monitoring --jupyter --llm
./tools/nemesis-ctl.sh start dev
./tools/nemesis-ctl.sh stop prod --monitoring --jupyter --llm
./tools/nemesis-ctl.sh clean prod --monitoring --jupyter --llm
```

### Development Setup

```bash
./tools/install_dev_env.sh
cd projects/web_api && uv sync
```

### Linting and Formatting

```bash
uv run ruff check . --fix
uv run ruff format .
cd projects/web_api && uv run ruff check . --fix
```

### Testing

```bash
cd projects/file_enrichment && uv run pytest tests/
cd projects/web_api && uv run pytest tests/test_specific.py
cd projects/web_api && uv run pytest tests/test_file.py::test_function_name
```

Testing standards:
- write tests for new features
- cover happy and unhappy paths
- mock external services in unit tests

### Docker Notes

Build base images first when rebuilding dev/prod containers:

```bash
docker compose -f compose.base.yaml build
```

Dapr-enabled services use `-dapr` sidecars. Rebuild both service and sidecar together.

## Architecture Snapshot

Tech stack:
- Python 3.13 with uv
- FastAPI services
- React 18 + Vite + TypeScript frontend
- PostgreSQL
- Dapr
- RabbitMQ
- Minio
- Traefik

Key directories:
- `projects/` microservices
- `libs/` shared Python libraries
- `infra/` infrastructure and workflows

Data flow summary:
1. Files uploaded via `web_api` or `cli` and stored in Minio.
2. `file_enrichment` consumes file events.
3. Dapr workflow orchestrates enrichment modules.
4. Results land in PostgreSQL; findings feed alerting.
5. Frontend surfaces results via Hasura GraphQL.
