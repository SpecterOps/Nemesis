# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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