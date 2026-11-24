# Enrichment API

**Version:** 0.1.0

API for file enrichment services

This documentation is automatically generated from the OpenAPI specification.

---

## Chatbot

### `POST /chatbot/stream`

Stream chatbot responses

Stream interactive chatbot responses for querying Nemesis data

**Request Body:** `ChatbotRequest` (JSON)

**Returns:** 200 on success

---


## Dpapi

### `POST /dpapi/credentials`

Submit DPAPI credential for masterkey decryption

Submit credential material to decrypt DPAPI master keys. Supports passwords, NTLM hashes, cred keys, domain backup keys, decrypted master keys, and Chromium app-bound-encryption keys.

**Request Body:** See OpenAPI spec for details

**Returns:** 200 on success

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


## File-Browser

### `GET /file-browser/children`

List one folder level of a source's file listings

Immediate sub-folders (first page only) and a keyset-paged list of files directly in `path`.

**Parameters:**

- `source` (string, **required**): file_listings source
- `path` (string, optional): Folder path without leading slash ('' for the root)
- `cursor` (unknown, optional): Return files after this path (next_cursor of the previous page)
- `limit` (integer, optional): Files per page
- `search` (unknown, optional): Case-insensitive substring filter on folder/file names

**Returns:** 200 on success

---

### `GET /file-browser/collection`

List paths that still need collection

Paged list of a source's needs_to_be_collected paths with the linkings that require them.

**Parameters:**

- `source` (string, **required**): file_listings source
- `offset` (integer, optional): 
- `limit` (integer, optional): 
- `search` (unknown, optional): Case-insensitive substring filter on the path

**Returns:** 200 on success

---

### `GET /file-browser/sources`

List file listing sources

All sources in file_listings with their total and per-status listing counts.

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

    `timestamp` and `expiration` must be ISO 8601 datetimes with a timezone (`Z` or an offset such as
    `+02:00`); times without one are rejected with 400. They are stored in UTC.

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
- `offset` (integer, optional): Byte offset to start reading from
- `length` (integer, optional): Number of bytes to read (0 = entire file)

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


## Reports

### `GET /reports/dashboard-stats`

Dashboard file and triage counts

File counts (total, submitted, derived, containers, unviewed) and findings counts by latest triage value (true_positive, false_positive, needs_review, untriaged), aggregated server-side.

**Returns:** 200 on success

---

### `GET /reports/source`

Get source report

Get detailed report for a specific source. Use query parameter to support sources with special characters (e.g., URLs)

**Parameters:**

- `source` (string, **required**): Source name (supports URLs and special characters, case-insensitive)
- `start_date` (unknown, optional): Filter by start date
- `end_date` (unknown, optional): Filter by end date

**Returns:** 200 on success

---

### `POST /reports/source/pdf`

Download source report as PDF

Generate and download a PDF report for a specific source. POST allows including pre-generated AI synthesis.

**Parameters:**

- `source` (string, **required**): Source name (supports URLs and special characters, case-insensitive)
- `start_date` (unknown, optional): Filter by start date
- `end_date` (unknown, optional): Filter by end date

**Request Body:** See OpenAPI spec for details

**Returns:** 200 on success

---

### `POST /reports/source/synthesize`

Generate LLM synthesis for source report

Generate AI-based risk assessment synthesis for a specific source. NOT CACHED - regenerated each time.

**Parameters:**

- `source` (string, **required**): Source name (supports URLs and special characters, case-insensitive)
- `include_findings_details` (boolean, optional): Include detailed findings in the analysis
- `max_tokens` (integer, optional): Maximum tokens for LLM analysis
- `start_date` (unknown, optional): Filter by start date (same filter as the source report/PDF)
- `end_date` (unknown, optional): Filter by end date (same filter as the source report/PDF)

**Returns:** 200 on success

---

### `GET /reports/sources`

List all sources

Get a list of all sources with summary statistics

**Parameters:**

- `project` (unknown, optional): Filter by project name
- `start_date` (unknown, optional): Filter by start date
- `end_date` (unknown, optional): Filter by end date

**Returns:** 200 on success

---

### `GET /reports/system`

Get system-wide report

Get system-wide statistics and findings across all sources

**Parameters:**

- `start_date` (unknown, optional): Filter by start date
- `end_date` (unknown, optional): Filter by end date
- `project` (unknown, optional): Filter by project name
- `sources_limit` (integer, optional): Max number of (most recently active) sources to include; 0 = all sources

**Returns:** 200 on success

---

### `GET /reports/system/pdf`

Download system-wide report as PDF

Generate and download a PDF report for the entire system

**Parameters:**

- `start_date` (unknown, optional): Filter by start date
- `end_date` (unknown, optional): Filter by end date
- `project` (unknown, optional): Filter by project name

**Returns:** 200 on success

---

### `POST /reports/system/synthesize`

Generate LLM synthesis for system report

Generate AI-based risk assessment synthesis for the entire system. NOT CACHED - regenerated each time.

**Parameters:**

- `max_tokens` (integer, optional): Maximum tokens for LLM analysis
- `start_date` (unknown, optional): Filter by start date
- `end_date` (unknown, optional): Filter by end date
- `project` (unknown, optional): Filter by project name

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

Trigger .NET assembly analysis in background (non-blocking)

**Request Body:** JSON object

**Returns:** 200 on success

---

### `POST /agents/llm_credential_analysis`

Run credential analysis

Trigger credential analysis in background (non-blocking)

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

Trigger text summarization in background (non-blocking)

**Request Body:** JSON object

**Returns:** 200 on success

---

### `POST /agents/translate`

Run text translation

Trigger text translation in background (non-blocking)

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

Reports 'healthy' when PostgreSQL and object storage are reachable, otherwise 'degraded' (always HTTP 200 so liveness probes don't restart the API over a dependency outage).

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

