# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [2.2.1]

### Added

- `CLAUDE.md` project file
- `enrichment-module-builder` skill triggered by `/new-enrichment-module` command for rapid file enrichment module development
- `prefetch` and `ccache` enrichment modules (developed by Claude skill)
- Proper GitHub issue templates


## [2.2.0]

### Added

- **DPAPI Auto-Decryption Pipeline**
  - Auto-decryption of Chromium cookies, saved passwords (Login Data), and Local State files
  - CNG/Chromekey file enrichment module with parsing and decryption
  - Chromium ABE v3 decryption via decrypted CNG keys
  - Retroactive decryption of Chromium data when plaintext masterkeys are submitted
  - `nemesis_dpapi` support library with Postgres backend, Dapr pubsub integration, and v3 masterkey support

- **File Linking System**
  - Enhanced file linking with path placeholders that resolve once matching files are collected
  - Programmatic registry hive and SYSTEM masterkey file linkings (replaces rule-based approach)
  - File Viewer support for deleting file linkings
  - File Browser displays collection reason and "Linked to by" fields

- **Large Container Processing**
  - Support for disk image formats and large archive processing
  - File monitoring for containers copied to `MOUNTED_CONTAINER_PATH` with automatic extraction and processing
  - Live-updating container tracking in dashboard ("Containers" tab)
  - Include/exclude filters for `/containers` API with CLI and submit.sh support

- **AI Agents & Triage**
  - Expanded agent infrastructure with JWT validation, finding triage, and text translation agents
  - Reporting summarization agent
  - LiteLLM integration with cost limits and Arize Phoenix tracing
  - Triage consensus scoring with confidence, explanation, and risk details
  - UI for editing agent prompts and viewing token spend statistics

- **Reporting**
  - System-wide and per-source reporting functionality
  - API endpoints for statistics and report PDF generation

- **Frontend**
  - Chromium page displaying history, downloads, cookies, logins, and state keys with filtering and CSV export
  - File Browser for navigating collected files
  - DPAPI viewer and submission pages
  - Drag/drop folder uploads
  - Agents page showing current agents and token spend stats

- **Infrastructure/Misc**
  - Velociraptor connector (server event YAML option)
  - NoseyParker scanning for zip files and .git repositories
  - Configurable alerting with enable/disable and filtering options
  - Multi-language Tika OCR support via `TIKA_OCR_LANGUAGES` environment variable
  - CLI `--folder` option to specify root folder path for uploads

### Changed

- Converted file_enrichment modules to async with shared DB connection pool and LRU caching
- Dapr pubsub components converted to task queues for improved performance and scaling
- Enrichment modules consolidated into single Dapr activity to reduce file download operations
- Bumped Dapr version to 1.16.1
- Updated Dapr state store to Postgres v2
- Path normalization standardized at initial ingestion
- DPAPIck3 now used for blob decryption
- CLI `--repeat` option renamed to `--times` (or `-x`), now defaults to 1

### Fixed

- Race condition when NoseyParker/DotNET findings arrive after file enrichment workflow completes
- Proper entropy handling for DPAPI blob decryption
- Path normalization bugs and duplicate normalization removed
- Tag search functionality
- Strings.txt exclusion from SQLite database processing
- Queue/workflow persistence with proper RabbitMQ queue restoration
- Various async issues and security dependency updates


## [2.1.4]

### Added

- Auto-decryption of Chromium and DPAPI related data:
  - Cookie and Login Data(saved passwords) DPAPI value decryption
  - Added Chromium UI page to display Cookie/Login Data
  - CNG/Chromekey file enrichment module (parser + decryptor)
  - Chromium ABE v3 decryption (via decrypted CNG keys)
- nemesis_dpapi support library:
  - Added Postgres support for DPAPI backend
  - Dapr pubsub integration for DPAPI-related event broadcasting
  - Added uniqueness and write constraints to prevent duplicate master/backup keys
  - Can now differentiate between user/system masterkeys
  - Added docs, examples, tests, and decryption benchmarks
  - Added support for v3 masterkeys decrypted with backup key
- New file enrichment modules:
  - `dpapi_masterkey` - Extracts encrypted masterkeys from user/system DPAPI masterkey files and decrypts them, if possible.
  - `exif_metadata` file enrichment module for supported image files
  - Added `cng_file`
- Added support for async code in Dapr activities used in enrichment modules
- Findings Page: Modified the Severities filter button to use checkboxes
- Multi-language Tika OCR support (`TIKA_OCR_LANGUAGES` ENV var, see `compose.yaml`)
- Text translation agent
- Retroactive DPAPI decryption:
  - Chromium Local State files when plaintext masterkeys are submitted/decrypted
  - Google Chromekeys (CNG file based), including decrypting applicable Local State files
  - Chromium Cookies/Login Data files
- File linking:
  - Enchanced file linking with placeholders in the path that resolve once a matching file is collected.
  - File Viewer: Added ability to delete file linkings from the FileViewer
  - File Browser: Added the collection reason and "Linked to by" fields on the "Files that need collection" option
- CLI: add a `--folder` option to the submit command that allows you to specify the path to the root folder of uploaded files.
- Reporting functionality
  - SYSTEM wide and per SOURCE
  - API endpoints for statistic and PDF generation (via Gotenberg conversion)
  - Reporting summarization agent
- Ability to enable/disable alerting, and filter alerts on specific criteria
- Performance:
  - Convert almost all of file_enrichment/file_enrichment_modules to using async
  - Made Dapr activities run in the asyncio loop
  - Use a shared DB connection pool
  - Use LRU cache for get_basic_enrichment calls
  - Identify how to manually scale containers in docker compose by manually creating replicas
  - Identified how to scale Dapr scheduler, if needed.
  - OTEL spans for various enrichment module components
  - Obtain prometheus metrics from Dapr components and other services.
- Allow configuring logging settings of various containers via env vars in compose file.
- `group_policy_preferences` and `mcafee_sitelist` file enrichment modules

### Changed

- Now use DPAPIck3 for blob decryption
- Bumped Dapr version to 1.16.1
- DPAPI_SYSTEM key pulled from registry parsing is now registered with the backend
- Updated category filters for frontend
- Collapsed inbound/outbound labels for linked files in dashboard
- Update Prometheus endpoints
- Chromium Local State, Cookies, and Login Data files now don't require hard paths
- Reg hive file linkings now done programmatically instead of via rules
- SYSTEM masterkey file linkings now done programmatically instead of via rules
- Added more details to errors that cause a workflow to die
- Optimized DPAPI masterkey decryption based on the type of masterkey
- Converted several DB calls to async code
- Optimized the housekeeping code to run in parallel and use transactions (where possible)
- CLI: Renamed `--repeat` option to `--times` (or `-x`) in submit command. Now defaults to 1 and represents total number of submissions (not additional submissions).
- UI: Changed the Dashboard "Files over time" graph adjust based on minutes/hours/days (rather than just default of days)
- Refactored how activities, subscriptions, and routes are created in the file_enrichment service.
- Simplified workflow tracking code
- Updated Dapr state store to Postgres v2
- Converted several subscriptions to use strongly typed Pydantic models
- UI - File Viewer:
  - Fixed "View Raw" triggering a download instead of opening in the browser
  - Restrict strings to 1 MB.
  - Cache files in memory to prevent re-downloading.
- Enabled Python dev mode in file_enrichment dev container
- Temporarily disable re-running of Yara rules until internal architecture for bulk enrichment re-running is fixed

### Fixed

- Properly use entropy for DPAPI blob decryption
- Lots of async issues
- Fixed tag search issue
- Fix to keep strings.txt from sqlite dbs from processing
- Path normalization: Fixed many bugs, removed lots of duplicate normalization, standardized normalization upon initial ingestion.
- Countless linting and other fixes
- Race condition when Nosey Parker / DotNET findings come in after the file enrichment workflow completes
  - TODO: in the future, remove pub/sub from these containers and have `file_enrichment` remotely schedule workflows in these containers
- Fixed container extraction status updates for large containers
- Converted all Dapr pubsub components to be task queues (not broadcast queues) to help with performance/scaling.
- Fixed several File resource leaks in office2john
- Normalized paths on upload instead of sprinkling normalization throughout codebase
- dotnet_service serialization errors on some assemblies
- Bumped various package versions to fix exposed dependabot security issues


## [2.1.3]

### Added

- "Chromium" page in the web frontend to display history, downloads, cookies, logins, and state keys
  - Includes filtering + CSV downloads for displayed data
- "File Browser" in the web frontend
- "DPAPI" viewer/submission pages in the web frontend
- Linked file tracking (via the ./libs/file_linking/ library)
  - Linked files exposed in the "File Browser" frontend and file viewer pages
- Adaptation of @Dreadnode's .NET reversing agent to `agents`
- "chromium" standard library in ./libs/ for parsing Chromium based files
- "nemesis_dpapi" library in ./libs/ for handling DPAPI related data/decryption
  - Includes in-memory storage of keys as well as postgres
  - Allows subscriptions to react to DPAPI-related events (e.g. new backup key, new plaintext masterkey, etc.)
- `registry_hive` parsing module that extracts bootkeys + local accounts + lsa secrets from linked hives
- Refactored file enrichment web API code to be more modular
- API route to submit DPAPI credential material
- Auto-building API documents for ./docs/api.md from the FastAPI routes in `web_api` container
- Documentation for "Containers" and LLM functionality
- Changed default FileList view to All Files, added unviewed indicator dot, and change search default to always include wildcards.

### Changed

- Standardize logging + fix suppressed logs
- DPAPI keys carved from LSASS dumps now saved via the nemesis_dpapi library

### Fixed

- Frontend live file reload
- `certificate` and `keytab` file enrichment modules


## [2.1.2] - 2025-08-22

### Added

- Ability to drag/drop folders onto the file upload page
- basic `triage` container greatly expanded to `agents`
  - JWT + finding validator agents implemented
  - Generalized/expandable agent infrastructure built
  - Confidence score, explanation, and risk detail returned by finding triage
  - "triage consensus" added for multiple triage values for the same file
- Tracing for `agents` added with Arize Phoenix (/phoenix, if --monitoring is enabled)
  - Token costs pulled from LiteLLM instance and manually synced to Phoenix for cost tracking
- Triage details added to finding table entries and findings modal
- Settings frontend page now has commit/build date/etc. info and Slack alert channel info (if configured)
- Repeat option added to submit script
- Conditionally shown "Agents" page in the frontend that shows current agents and token spend stats
  - Also allows for editing Agent prompts in the UI

### Changed

- "explanation" field added to the findings_triage_history table in the schema
- Help page in frontend only shows routes for services that are enabled
- Logs suppressed during Dapr replay (only show on first run)
- Removed loud FastAPI tracer
- Enrichment modules rolled into one activity (no longer each their own) for optimization
  - Also means a reduction in file download actions for enrichment modules - modules modified to support this
- LLM credential analysis and text summarization enrichment modules ported to `agents`

### Fixed

- Markdown escape for displayed extracted hashes
- Fixed PE parsing not throwing an exception
- Fixed runtime deprecation warning
- Maintain references to various asyncio tasks


## [2.1.1] - 2025-08-01

### Added

- LiteLLM server (with "llm" profile in Docker) to serve future LLM integrations
  - Includes cost limits
- Display/linking to originating container for files derived from containers
- Support for include/exclude filters for the `/containers` API
  - Added filter support into `cli` container + submit.sh
- Processing for a number of disk image formats
- File monitoring for (large) containers copied to MOUNTED_CONTAINER_PATH
  - Containers have files extracted + processed
  - Used for workflows with very large containers/disk images
- Velociraptor connector (server event .yaml option)
- `noseyparker_scanner` now can scan zips and .git repos
  - Includes relevant match info in results (can be set by ENV vars)

### Changed

- Expired containers now cleaned up
- Made "timestamp" and "expiration" submission fields optional (filled with defaults)
- Bumped Dapr version to 1.15.8
- Filtering by URL for containers
- Bulk enrichment system now uses pub/sub
- `triage` connecter now uses LiteLLM for models via Rigging
- Pagination in FileList view for large number of files

### Fixed

- "source" field propagation for containers
- Container filtering in dashboard
- Arguments with value ordering error in submit.sh


## [2.1.0] - 2025-07-20

### Added

- Retries for submit.py
- `3_workflow_performance.ipynb` Jupyter notebook to assess pipeline performance
- "source" field (to represent hostname, source site, etc.) integrated into schema + frontend
- Start of bulk-enrichment re-rerunning, including re-running Yara rules from the dashboard
- New system for large "container" triaging
  - New `/api/containers` route
  - Container process tracking system using pub/sub from `file_enrichment` -> `web_api`
  - Live updating container tracking in the dashboard (new "Containers" tab)
  - submit.sh/monitor.sh scripts now can submit "containers"
- Internal queues now cleaned on up system delete/reset
- PostgreSQL NOTIFY/LISTEN system for `file_enrichment` workers

### Changed

- Timeouts/improved submit logic for the web_api
- Bumped Dapr version to 1.15.6
- Combined `dotnet_api` and `InspectAssembly` into single, streamlined pure .NET `dotnet_service` container
- Eliminated the internal file-enrichment queue
  - Now relies on the Dapr pub/sub queue (RabbitMQ) to provide backpressure
- Stale workflows periodically cleaned up

### Fixed

- Limits/concurrency fixes for NoseyParker scanner to prevent OOM errors
- Implemented queue/workflow persistence
  - RabbitMQ queues now restored properly even if containers are completely removed
  - In-flight workflows re-submitted for processing


## [2.0.1]

### Changed

- Conditionally start trace logging
- Reverted Grafana to anonymous auth (still behind common basic auth)
- Dashboard status updates on Yara engine reloads for rule changes

### Fixed

- Yara rule match errors when a rule description wasn't present
- Don't exit when `cli` folder monitoring starts on an empty folder
- Fix for using custom SSL certificates


## [2.0.0] - 2025-06-27

Complete, nearly ground-up rewrite of the 1.0 branch.

### Changed

- Almost too many things to count.
- k3s support dropped (for now) for Docker for more rapid development
- General-data-modeling approach abandoned to focus (for now) solely on file enrichment
    - MASSIVELY simplify the data schema: just `file` and `file_enriched`
- Droped rarely-used, performance heavy functionality (NLP embedding models, top 10k password cracking, etc.)
- Eliminated Elasticsearch, relying solely on Postgres for final data storage.
- Heavy [Dapr](https://dapr.io/) integration including Dapr workflows for durability + tracing
- Completely new, custom React dashboard (dropping Streamlit)
- Introduced "findings" and "transforms" concepts emitted from process files
- Alerting generalized with [Apprise](https://github.com/caronc/apprise/)
- New alerting/logging/tracing infrastructure (Loki, Jaeger, etc.)
- Dynamic Yara rule deployment
- Dropped S3 support (for now) - solely local Minio for datalake
- Dropped Protobufs for increased flexibility
- `cli` now Docker based
- Production now building + publishing via GitHub actions/workflows
- Customized Nosey Parker Rust service
- Several file enrichment modules added
- Jupyter notebooks added


## [1.0.0] - 2024-04-25

### Added

- Proper host and temporal modeling
- Helm charts for deployment and publishing of images to [Dockerhub](https://hub.docker.com/u/specterops)
- Hasura API endpoint
- Additional documentation, including (finally) a usage guide
- Hosting of documentation on [GitHub Pages](https://specterops.github.io/Nemesis/)
- `monitor` command to submit_to_nemesis.sh for continual file submission
- Jupyter notebooks back into the stack
- Processing for Chromium JSON cookie dumps
- Automatic expunging of expired data via the `data_expunge` task

### Changed

- Dropped Docker/Minikube support, replaced with k3s
- Drastically simplified/streamlined setup process
- Any compatible file is now handled by Apache Tika instead of a subset
- Removed the Tensorflow model hosting and DeepPass as the model just wasn't accurate enough to be useful
- Streamlined NLP indexing to prevent choking and exposed a /nlp/ route for search
- Streamlined hash cracking and added in deduplication so hashes aren’t cracked twice
- Revamped text search to use fuzzy search fused with semantic search
- Countless Dashboard changes

### Fixed

- Too many bugs to count