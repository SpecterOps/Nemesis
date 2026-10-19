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

### Connector startup checks

Normal C2 connector runs (Mythic, Outflank, and Cobalt Strike) check Nemesis at
`/api/system/health` before connecting to their C2 server. The check uses the
configured Nemesis credentials and certificate validation setting. Its timeout is
`conn_timeout_sec` for Cobalt Strike and Outflank, and `networking.timeout_sec`
for Mythic.
Mythic then validates its GraphQL login, current operation, and `filemeta` access
before opening its durable discovery stream. Transient Mythic session failures
reconnect after 1, 2, 4, 8, 16, then 30 seconds; a session healthy for at least
60 seconds resets that delay. Authentication, authorization, schema, and database
failures stop the connector with a nonzero exit status.

If Nemesis is unreachable, rejects authentication, returns an invalid response,
or reports an unhealthy status, the connector logs the failure and exits with status 1.

Connector uploads use one pooled async Nemesis client per run, shared by the
startup health check and file processors. At most four uploads run concurrently.
Connection establishment and pool waits use the connector's configured timeout;
upload reads and writes allow up to 520 seconds of inactivity. Only connection
establishment failures are retried, up to three attempts with one- and two-second
delays. HTTP responses and failures after connection establishment are returned
without retry.

All three C2 connectors support `--dry-run`. They still authenticate to the C2
platform and download files, then log `WOULD UPLOAD` with each file's original
path, project, source, byte count, and SHA-256. They skip Nemesis health checks
and uploads. Dry runs use a temporary cache that is removed on exit.

```bash
uv run python -m cli connect-mythic --config settings_mythic.yaml --dry-run
uv run python -m cli connect-outflank --config settings_outflank.yaml --dry-run
uv run python -m cli connect-cobaltstrike --config settings_cobaltstrike.yaml --dry-run
```

The Mythic connector stores its discovery cursor and pending file UUIDs in
LevelDB, scoped to the Mythic URL and selected operation. Existing
`filemeta<agent-file-uuid>` success markers remain valid after upgrade. It
discovers incomplete file records too, then watches pending files through live
GraphQL subscriptions in batches of up to 100 IDs. Completion and deletion
updates arrive over WebSockets; there is no periodic connector metadata polling.
Hasura evaluates live queries every second by default. Pending subscriptions
receive a fresh snapshot after reconnecting, using the saved queue. Failed
transfers still use retry timers even if no further metadata updates arrive.
Transient failures retry after 5, 10, 20, 40, 80, 160, then 300 seconds. If Nemesis accepted a file but
the connection failed before its response arrived, a retry may submit a
duplicate; delivery is at least once while the remote outcome is uncertain.

### connect-mythic
Synchronize data between Mythic C2 framework and Nemesis.

**Configuration:**
- Uses `settings_mythic.yaml` configuration file
- `--showconfig`: Display example configuration
- `--dry-run`: Download files and log upload previews without contacting Nemesis

### connect-outflank
Ingest data from Outflank Stage1 C2 into Nemesis.

**Configuration:**
- Uses `settings_outflank.yaml` configuration file
- `--showconfig`: Display example configuration
- `--dry-run`: Download files and log upload previews without contacting Nemesis

### connect-cobaltstrike
Ingest data from Cobalt Strike into Nemesis.

A Cobalt Strike startup or monitor failure exits with status 1 and cancels any
other running monitors.

**Configuration:**
- Uses `settings_cobaltstrike.yaml` configuration file
- `--showconfig`: Display example configuration
- `--dry-run`: Download files and log upload previews without contacting Nemesis

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

2. Install system dependencies required for building native packages:
```bash
# Debian/Ubuntu
sudo apt-get install -y libleveldb-dev

# macOS
brew install leveldb
```

3. Install dependencies and run it:
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
