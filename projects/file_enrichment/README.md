# File Enrichment Service

A microservice for the Nemesis platform that orchestrates comprehensive file analysis through specialized enrichment modules.

## Purpose

This service coordinates the analysis of uploaded files by running them through various enrichment modules to extract metadata, credentials, and other valuable information. It serves as the core processing engine for file intelligence gathering in the Nemesis platform.

## Features

- **Modular analysis**: Supports 20+ specialized enrichment modules for different file types and use cases
- **Workflow orchestration**: Uses Dapr workflows to manage complex multi-step analysis processes
- **Parallel processing**: Executes multiple enrichment modules concurrently with configurable limits
- **Container extraction**: Processes archives and containers to analyze nested files
- **Feature extraction**: Automatically determines file characteristics and selects appropriate modules
- **NoseyParker integration**: Performs secret scanning on text-based files
- **Rate limiting**: Controls resource usage with configurable concurrency limits

## Enrichment Modules

The service includes specialized modules for:

### Credential Extraction
- **DPAPI**: Windows Data Protection API credentials
- **Keytab**: Kerberos keytab files
- **Git credentials**: Git configuration and credential files
- **Putty registry**: Putty session configurations
- **Filezilla**: FTP client configurations

### File Format Analysis
- **PE files**: Windows executables and DLLs
- **Office documents**: Microsoft Office file analysis
- **PDFs**: Portable Document Format analysis
- **SQLite**: Database file analysis
- **Certificates**: X.509 certificate parsing

### System Configuration
- **Sysprep**: Windows system preparation files
- **Unattend XML**: Windows deployment configurations
- **VNC ini**: VNC configuration files
- **LNK files**: Windows shortcut analysis

### Application Data
- **Chromium history**: Browser history extraction
- **Slack data**: Slack workspace analysis
- **Container contents**: Archive and container processing

### Security Analysis
- **YARA**: Malware detection and classification
- **PII detection**: Personally identifiable information scanning
- **Text summarization**: LLM-powered content analysis
- **Base64 decoding**: Automatic encoding detection and decoding

## Configuration

Environment variables for tuning performance:

- `MAX_WORKFLOW_EXECUTION_TIME`: Workflow timeout in seconds (default: 300)
- `WORKFLOW_RUNTIME_LOG_LEVEL`: Workflow engine logging level (default: WARNING)

## Workflow Process

1. **File ingestion**: Receives file events from the platform
2. **Feature extraction**: Analyzes file metadata and characteristics
3. **Module selection**: Determines which enrichment modules to run
4. **Parallel execution**: Runs selected modules concurrently
5. **Container processing**: Extracts and processes nested files if applicable
6. **Result storage**: Saves enrichment results to the database
7. **Alert generation**: Triggers notifications for significant findings

## Health Monitoring

- Distributed tracing with OpenTelemetry
- PostgreSQL connection pooling
- Workflow status tracking
- Module execution metrics


# Debugging
1. Start everything:
```bash
NEMESIS_MONITORING=enabled \
ENVIRONMENT=dev \
LOG_LEVEL=debug \
DAPR_LOG_LEVEL=warn \
docker compose -f compose.yaml \
  -f compose.prod.build.yaml \
  -f projects/file_enrichment/docker-compose.debug.yml \
  --profile monitoring \
  up -V -d --no-deps -V --wait
```

2. Launch the debugged application in VS code (F5)

3. Now that it's running, restart the file enrichment services:
```bash
NEMESIS_MONITORING=enabled \
ENVIRONMENT=dev \
LOG_LEVEL=debug \
DAPR_LOG_LEVEL=warn \
docker compose -f compose.yaml \
  -f compose.prod.build.yaml \
  -f projects/file_enrichment/docker-compose.debug.yml \
  --profile monitoring \
  up -V -d --no-deps -V --wait \
  file-enrichment file-enrichment-dapr
```