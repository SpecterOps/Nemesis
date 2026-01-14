# Web API Service

A FastAPI-based microservice for the Nemesis platform that provides the primary HTTP API for file management, workflow orchestration, and system operations.

## Purpose

This service serves as the main entry point for external interactions with the Nemesis platform, providing RESTful endpoints for file uploads, downloads, enrichment management, and workflow monitoring. It acts as a gateway that coordinates between the frontend interface, file storage, and various processing services.

## Features

### File Management
- **File upload**: Multi-part form uploads with metadata validation
- **File download**: Streaming downloads with size limits and custom filenames
- **Storage integration**: Direct integration with Minio object storage
- **Metadata handling**: JSON-based file metadata processing and validation

### Workflow Operations
- **Status monitoring**: Real-time workflow status and metrics
- **Failed workflow tracking**: Access to failed enrichment workflows
- **Queue management**: Visibility into workflow queues and active processing

### Enrichment Management
- **Module listing**: Discovery of available enrichment modules
- **LLM integration**: Access to enabled LLM-powered enrichment modules
- **Manual execution**: Trigger specific enrichment modules on files
- **Service proxy**: Forwards enrichment requests to the file-enrichment service

### System Operations
- **Health monitoring**: Comprehensive health checks for service status
- **YARA management**: Reload YARA rules across the platform
- **Cleanup operations**: Data retention and cleanup functionality
- **API documentation**: Auto-generated OpenAPI/Swagger documentation

## API Endpoints

### Files (`/files`)
- `POST /files`: Upload files with metadata
- `GET /files/{object_id}`: Download files by object ID

### Workflows (`/workflows`)
- `GET /workflows/status`: Get enrichment workflow status and metrics
- `GET /workflows/failed`: Retrieve failed workflow details

### Enrichments (`/enrichments`)
- `GET /enrichments`: List all available enrichment modules
- `GET /enrichments/llm`: List enabled LLM enrichment modules
- `POST /enrichments/{module_name}`: Execute specific enrichment module

### System (`/system`)
- `GET /healthz`: Service health check
- `POST /yara/reload`: Reload YARA rules
- `POST /cleanup`: Trigger data cleanup operations

## Configuration

- `DOWNLOAD_SIZE_LIMIT_MB`: Maximum file download size (default: 500MB)
- `DEFAULT_EXPIRATION_DAYS`: Default file expiration period (default: 100 days)
- `DAPR_HTTP_PORT`: Dapr sidecar port for service communication (default: 3500)

## Integration

- **Dapr**: Service-to-service communication and pub/sub messaging
- **Minio**: Object storage for file management
- **File Enrichment Service**: Forwards enrichment requests and monitoring
- **Frontend**: Serves API requests from the web interface

## API Documentation

Interactive API documentation available at `/api/docs` (Swagger UI) and `/api/redoc` (ReDoc) when the service is running.

---

## Development

### Usage
To run locally:
```bash
uv run uvicorn web_api.main:app --reload
```

### Debugging
**NOTE:** These instructions need to be updated!

1. Open the `web_api` folder in VS Code
2. Hit `F5` to launch the application with the debugger attached
3. Start up Nemesis in dev mode, enabling debugging for the web_api:

```bash
cd Nemesis
docker compose up -f compose.yaml -f compose.override.yaml -f ./projects/web_api/docker-compose.debug.yml
```

This exposes Minio's port so the `web_api` can upload files outside the cluster. In addition, it isolates the `web_api` instance deployed by `docker compose` and informs its sidecar about the debugged `web_api` instance that's running in VS Code.

### Docker Images
1. If the base images haven't been built yet, do that first:
```bash
cd nemesis
docker compose -f docker-compose.base.yml build
```

2. Build the dev or prod image:
```bash
# dev
# cd web_api
docker build -f Dockerfile -t nemesis-web-api --target dev ../..
```
```bash
# prod
# cd web_api
docker build -f Dockerfile -t nemesis-web-api --target prod ../..
```