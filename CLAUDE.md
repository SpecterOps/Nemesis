# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## File Restrictions

**NEVER read, open, or access `.env` files under any circumstances.** This includes:
- `.env`
- `.env.local`
- `.env.development`
- `.env.production`
- Any file matching the pattern `.env*`

If you need environment variable information, refer to `env.example` instead.

## Project Overview

Nemesis is an open-source, centralized data processing platform (v2.0) that ingests, enriches, and enables collaborative analysis of files collected during offensive security assessments. Built on Docker with Dapr integration, it functions as an "offensive VirusTotal."

## Common Commands

### Running Nemesis

```bash
# Start production services
./tools/nemesis-ctl.sh start prod

# Start with monitoring, jupyter, and LLM support
./tools/nemesis-ctl.sh start prod --monitoring --jupyter --llm

# Start development environment (always builds)
./tools/nemesis-ctl.sh start dev

# Stop services (use same flags as start)
./tools/nemesis-ctl.sh stop prod --monitoring --jupyter --llm

# Stop and remove volumes
./tools/nemesis-ctl.sh clean prod --monitoring --jupyter --llm
```

### Development Setup

```bash
# Install all uv dependencies across projects
./tools/install_dev_env.sh

# Install dependencies for a single project
cd projects/web_api && uv sync
```

### Linting & Formatting (Ruff)

```bash
# Check all Python code (configured in root pyproject.toml)
ruff check .

# Format code
ruff format .

# Check specific project
cd projects/web_api && uv run ruff check .
```

### Testing

```bash
# Run tests for a specific project
cd projects/file_enrichment && uv run pytest tests/

# Run single test file
cd projects/web_api && uv run pytest tests/test_specific.py

# Run specific test
cd projects/web_api && uv run pytest tests/test_file.py::test_function_name
```

### Docker Commands

```bash
# Build base images first (required before building services)
docker compose -f compose.base.yaml build

# View logs for a service
docker compose logs -f web-api

# Rebuild and restart single service
docker compose up -d --build web-api
```

## Architecture

### Tech Stack
- **Python 3.12-3.13** with uv for dependency management
- **FastAPI** for REST services
- **React 18 + Vite + TypeScript** for frontend
- **PostgreSQL** for database
- **Dapr** for pub/sub, workflows, secrets, and service invocation
- **RabbitMQ** for message queue
- **Minio** for object storage
- **Traefik** for reverse proxy

### Directory Structure

```
projects/           # Microservices
├── web_api/        # FastAPI REST gateway (port 8000)
├── file_enrichment/# File analysis orchestration with Dapr workflows
├── document_conversion/ # Text extraction, PDF conversion
├── cli/            # Command-line file submission tool
├── frontend/       # React web UI
├── alerting/       # Apprise-based notification service
├── housekeeping/   # Cleanup/retention service
├── agents/         # AI-powered alert triage
├── jupyter/        # Jupyter notebook service
├── dotnet_service/ # .NET assembly analysis service
├── noseyparker_scanner/ # Secret scanning with NoseyParker
├── velociraptor_connector/ # Velociraptor integration
└── ...

libs/               # Shared Python libraries
├── common/         # DB connections, logging, models, Dapr wrappers
├── file_enrichment_modules/ # 20+ enrichment module implementations
├── chromium/       # Chrome/Edge data extraction
├── file_linking/   # File association logic
└── nemesis_dpapi/  # Windows DPAPI credential handling

infra/              # Infrastructure configuration
├── dapr/           # Dapr components and workflows
├── postgres/       # Database schema (01-schema.sql)
├── grafana/        # Monitoring dashboards
└── ...
```

### Data Flow
1. Files uploaded via **web_api** or **cli** → stored in **Minio**
2. **file_enrichment** receives file events via Dapr pub/sub
3. Dapr workflow orchestrates enrichment modules in parallel
4. Results written to **PostgreSQL**, findings published for alerting
5. **frontend** displays results via Hasura GraphQL

### Key Configuration
- Root `pyproject.toml`: Ruff linting config (line-length: 120, Python 3.12)
- `.env`: Passwords, URLs, feature flags (copy from `env.example`)
- `infra/postgres/01-schema.sql`: Database schema

### Adding Enrichment Modules
New file enrichment modules go in `libs/file_enrichment_modules/`. Each module implements a standard interface for detecting applicable files and extracting data.
