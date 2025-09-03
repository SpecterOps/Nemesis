# Enrichment API

**Version:** 0.1.0

API for file enrichment services

This documentation is automatically generated from the OpenAPI specification.

---

## Enrichments

### `GET /enrichments`

List enrichment modules

Get a list of all available enrichment modules

**Returns:** 200 on success

---

### `POST /enrichments/{enrichment_name}`

Run enrichment module

Run a specific enrichment module on a file

**Parameters:**

- `enrichment_name` (string, **required**): Name of the enrichment module to run

**Request Body:** `EnrichmentRequest` (JSON)

**Returns:** 200 on success

---

### `POST /enrichments/{enrichment_name}/bulk`

Start bulk enrichment

Start bulk enrichment for a specific module against all files in the system using distributed processing

**Parameters:**

- `enrichment_name` (string, **required**): Name of the enrichment module to run

**Returns:** 200 on success

---

### `GET /enrichments/{enrichment_name}/bulk/status`

Get bulk enrichment status

Bulk enrichment status tracking has been simplified

**Parameters:**

- `enrichment_name` (string, **required**): Name of the enrichment module to check status for

**Returns:** 200 on success

---

### `POST /enrichments/{enrichment_name}/bulk/stop`

Stop bulk enrichment

Bulk enrichment cannot be stopped once tasks are published

**Parameters:**

- `enrichment_name` (string, **required**): Name of the enrichment module to stop

**Returns:** 200 on success

---


## Files

### `POST /containers`

Submit large container file for processing with optional filtering

...

**Request Body:** See OpenAPI spec for details

**Returns:** 200 on success

---

### `GET /containers/{container_id}/status`

Get container processing status

Get the current processing status and progress of a submitted container

**Parameters:**

- `container_id` (string, **required**): Unique identifier of the container

**Returns:** 200 on success

---

### `POST /files`

Upload file with metadata

Upload a file using multipart/form-data with metadata.
    Returns an object_id for the uploaded file and submission_id for the metadata submission.

    Example:
    ```
    curl -k -u n:n -F "file=@example.txt"          -F 'metadata={"agent_id":"agent123","project":"proj1","timestamp":"2024-01-29T12:00:00Z","expiration":"2024-02-29T12:00:00Z","path":"/tmp/example.txt"}'          https://nemesis:7443/api/files
    ```

    Example:
    ```
    curl -k -u n:n -F "file=@example.txt"          -F 'metadata={"agent_id":"agent123","project":"proj1","path":"/tmp/example.txt"}'          https://nemesis:7443/api/files
    ```

**Request Body:** See OpenAPI spec for details

**Returns:** 200 on success

---

### `GET /files/{object_id}`

Download a file

Download a file by its object ID with optional raw format and custom filename

**Parameters:**

- `object_id` (string, **required**): Unique identifier of the file to download
- `raw` (boolean, optional): Whether to return the file in raw format
- `name` (string, optional): Custom filename for the downloaded file

**Returns:** 200 on success

---


## Queues

### `GET /queues`

Get queue statistics

Get comprehensive queue metrics for all workflow topics

**Returns:** 200 on success

---

### `GET /queues/{queue_name}`

Get single queue statistics

Get metrics for a specific queue topic

**Parameters:**

- `queue_name` (string, **required**): Name of the queue to get metrics for

**Returns:** 200 on success

---


## System

### `GET /agents`

Get available agents

Get a list of available AI agents with their metadata and capabilities

**Returns:** 200 on success

---

### `POST /agents/dotnet_analysis`

Run .NET assembly analysis

Forward .NET assembly analysis request to agents service

**Request Body:** JSON object

**Returns:** 200 on success

---

### `POST /agents/llm_credential_analysis`

Run credential analysis

Forward credential analysis request to agents service

**Request Body:** JSON object

**Returns:** 200 on success

---

### `GET /agents/spend-data`

Get LLM spend and usage data

Get total spend and token usage statistics from LiteLLM logs

**Returns:** 200 on success

---

### `POST /agents/text_summarizer`

Run text summarization

Forward text summarization request to agents service

**Request Body:** JSON object

**Returns:** 200 on success

---

### `GET /system/apprise-info`

Get Apprise alert information

Get information about configured alert channels (currently Slack only)

**Returns:** 200 on success

---

### `GET /system/available-services`

Get available services

Query Traefik to determine which optional services are currently available

**Returns:** 200 on success

---

### `POST /system/cleanup`

Trigger database and datalake cleanup

Trigger the housekeeping service to clean up expired files and database entries, and reset the workflow manager state. Optionally specify an expiration date or 'all' to remove all files.

**Request Body:** `CleanupRequest` (JSON)

**Returns:** 200 on success

---

### `GET /system/container-monitor/status`

Container monitor status

Get the status of the container file monitor

**Returns:** 200 on success

---

### `GET /system/health`

Health check

Health check endpoint for Docker healthcheck

**Returns:** 200 on success

---

### `GET /system/info`

API information

Root endpoint that shows API information

**Returns:** 200 on success

---

### `POST /system/yara/reload`

Reload Yara rules

Trigger a reload of all Yara rules in the backend across all workers/replicas

**Returns:** 200 on success

---


## Workflows

### `GET /workflows/failed`

Get failed workflows

Get the set of failed enrichment workflows

**Returns:** 200 on success

---

### `GET /workflows/status`

Get workflow enrichment workflow status

Get the current status of the enrichment workflow system

**Returns:** 200 on success

---

