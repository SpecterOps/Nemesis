# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1]

### Changed

- Conditionally start trace logging
- Reverted Grafana to anonymous auth (still behind common basic auth)
- Dashboard status updates on Yara engine reloads for rule changes

### Fixed

- Yara rule match errors when a rule description wasn't present
- Don't exit when `cli` folder monitoring starts on an empty folder


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