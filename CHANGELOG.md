# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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