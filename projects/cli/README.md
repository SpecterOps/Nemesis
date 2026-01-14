# Nemesis CLI

A command-line interface for the Nemesis platform that provides file submission, monitoring, and C2 connector functionality.

## Purpose

This CLI tool serves as the primary interface for uploading files to Nemesis, monitoring directories for new files, and synchronizing data from C2 frameworks like Mythic, Cobalt Strike and Outflank.

## Features

- **File submission**: Upload single files or entire directories to Nemesis
- **Directory monitoring**: Real-time monitoring of folders for new files
- **C2 connectors**: Synchronize data from Mythic, Cobalt Strike and Outflank C2 frameworks
- **Stress testing**: Load testing capabilities for the Nemesis API
- **Module testing**: Execute file enrichment modules standalone for development

## Commands

### submit
Upload files or directories to Nemesis for processing.

**Key options:**
- `-r, --recursive`: Process subdirectories recursively
- `-w, --workers`: Number of concurrent upload threads (default: 10)
- `--project`: Project name for metadata (default: assess-test)
- `--agent-id`: Agent identifier for tracking uploads

### monitor
Monitor a directory for new files and automatically submit them to Nemesis.

**Key options:**
- `--only-monitor`: Skip existing files, only watch for new ones
- `-w, --workers`: Number of threads for initial submission

### connect-mythic
Synchronize data between Mythic C2 framework and Nemesis.

**Configuration:**
- Uses `settings_mythic.yaml` configuration file
- `--showconfig`: Display example configuration

### connect-outflank
Ingest data from Outflank Stage1 C2 into Nemesis.

**Configuration:**
- Uses `settings_outflank.yaml` configuration file
- `--showconfig`: Display example configuration

### connect-cobaltstrike
Ingest data from Cobalt Strike into Nemesis.

**Configuration:**
- Uses `settings_cobaltstrike.yaml` configuration file
- `--showconfig`: Display example configuration

## Additional Tools

- **stress_test**: Load testing tool for API performance evaluation
- **module_runner**: Standalone execution of file enrichment modules for development and testing

## Authentication

All commands support basic authentication with configurable username and password options (default: n/n).

# Manually running with Python
1. Navigate to the cli directory. Perform all the following steps from this directory.
```bash
cd Nemesis/projects/cli
```

2. Install dependencies and run it:
```bash
uv sync
uv run python -m cli
```

# Manually Building and Using with Docker
1. Navigate to the cli directory. Perform all the following steps from this directory.
```bash
cd Nemesis/projects/cli
```

2. Build the base images:
```bash
docker compose -f ../../compose.base.yaml build
```

3. Build the nemesis-cli image:
```bash
docker build -t nemesis-cli --target prod --no-cache -f Dockerfile ../..
```
Validate `--target` arguments are `prod` or `dev`.


4. Run the nemesis-cli container:
```bash
docker run --network host -v /:/data --rm nemesis-cli submit /data/etc/issue
```

# Using Docker Compose
## Pull the published production image and run it
1. Navigate to the cli directory. Perform all the following steps from this directory.
```bash
cd Nemesis/projects/cli
```

2. Pull the published production container and run it:
```bash
docker compose -f compose.yaml run --rm cli
```

## Build and run the dev/production images
1. Navigate to the cli directory. Perform all the following steps from this directory.
```bash
cd Nemesis/projects/cli
```

2. Build the base images:
```bash
docker compose -f ../../compose.base.yaml build
```

3. Build and run the dev or production containers.

To run the development container, run the following. This mounts CLI's code into container and uses the dev base image. It implicitly merges compose.yaml and compose.override.yaml.
```bash
docker compose run --rm cli
```

Alternatively, you can build the production image and run it with the following:
```bash
docker compose -f compose.yaml -f compose.prod.build.yaml run --rm cli
```


# Using submit.sh (in dev)
## Building the dev image
1. Navigate to the cli directory. Perform all the following steps from this directory.
```bash
cd Nemesis/projects/cli
```

2. Build the base images:
```bash
docker compose -f ../../compose.base.yaml build
```

3. Build the nemesis-cli image:
```bash
docker build -t nemesis-cli --target dev --no-cache -f Dockerfile ../..
```

4. Export NEMESIS_CLI_IMAGE
```bash
export NEMESIS_CLI_IMAGE=nemesis-cli:latest
```

5. Run ./submit.sh as normal:
```bash
cd ../..
./tools/submit.sh --help
```
