# Nemesis CLI

The Nemesis CLI provides tools for interacting with the Nemesis platform, including file submission and data synchronization with external C2 frameworks.

## Overview

The CLI supports four main operations:

- **File Submission**: Upload files directly to Nemesis for processing
- **Folder Monitoring**: Monitor a folder for new files and submit them to Nemesis for processing
- **Mythic Connector**: Synchronize data between Mythic C2 and Nemesis
- **Outflank Connector**: Ingest data from Outflank Stage1 C2 into Nemesis

## Installation & Setup

### Docker Method (Recommended)

The CLI is containerized and auto-built with the rest of the containers on `docker compose up`.

The helper scripts `./tools/submit.sh`, `./tools/monitor_folder.sh`, and `./tools/mythic_connect.sh` wrap the required docker compose syntax for ease of use.

After building, commands can be run with:

```bash
# Run CLI commands
docker compose run --rm cli <command>
```

### Poetry Method (Development)

For development or local installation:

```bash
cd projects/cli
poetry install
poetry run python -m cli <command>
```

## File Submission

Submit files to Nemesis for processing and enrichment.

The `./tools/submit.sh` script wraps the docker compose syntax automatically.

### Basic Usage

**./tools/submit.sh (easiest option, preferred) :**
```bash
# Submit a single file
./tools/submit.sh /path/to/file

# Submit multiple files
./tools/submit.sh /path/to/file1 /path/to/file2

# Submit directory
./tools/submit.sh /path/to/directory/

# Submit directory recursively (-r or --recursive)
./tools/submit.sh -r /path/to/directory/
```

**docker compose :**
```bash
# Submit a single file
docker compose run --rm -v /path/to/file:/data/file cli submit /data/file

# Submit multiple files
docker compose run --rm -v /path/to/directory:/data cli submit /data/file1 /data/file2

# Submit directory recursively
docker compose run --rm -v /path/to/directory:/data cli submit /data --recursive
```

**Poetry :**
```bash
# Submit a single file w/ Poetry env
poetry run python -m cli submit /data/file
```

### Advanced Options

**./tools/submit.sh (easiest option, preferred) :**
```bash
./tools/submit.sh /data/file \
  --host nemesis.example.com:7443 \
  --username your-username \
  --password your-password \
```

**docker compose :**
```bash
docker compose run --rm -v /path/to/files:/data cli submit /data \
  --host nemesis.example.com:7443 \
  --username your-username \
  --password your-password \
  --project my-project \
  --agent-id my-agent \
  --workers 5 \
  --recursive \
  --debug
```

### Options Reference

**See all ./tools/submit.sh options:**
```bash
% ./tools/submit.sh --help
Usage: python -m cli submit [OPTIONS] PATHS...

  Submit files to Nemesis for processing

Options:
  --debug                Enable debug logging
  -h, --host TEXT        Host and port in format HOST:PORT  [default:
                         0.0.0.0:7443]
  -r, --recursive        Recursively process subdirectories
  -w, --workers INTEGER  Number of worker threads  [default: 10]
  -u, --username TEXT    Basic auth username  [default: n]
  -p, --password TEXT    Basic auth password  [default: n]
  --project TEXT         Project name for metadata  [default: assess-test]
  --agent-id TEXT        Agent ID for metadata  [default:
                         submitunknown_user@docker-desktop]
  -f, --file FILE        Path to single file to submit (alternative to PATHS
                         for backwards compatibility)
  --help                 Show this message and exit.
```

| Option        | Default               | Description                  |
| ------------- | --------------------- | ---------------------------- |
| `--host`      | `0.0.0.0:7443`        | Nemesis host and port        |
| `--recursive` | `false`               | Process subdirectories       |
| `--workers`   | `10`                  | Number of upload threads     |
| `--username`  | `n`                   | Basic auth username          |
| `--password`  | `n`                   | Basic auth password          |
| `--project`   | `assess-test`         | Project name for metadata    |
| `--agent-id`  | `submit<user>@<host>` | Agent ID for metadata        |
| `--debug`     | `false`               | Enable debug logging         |

## Folder Monitoring

Monitor a folder for new files and automatically submit them to Nemesis for processing. This includes both existing files (optional) and any new files added to the folder while monitoring is active.

The `./tools/monitor_folder.sh` script wraps the docker compose syntax automatically.

### Basic Usage

**./tools/monitor_folder.sh (easiest option, preferred) :**
```bash
# Monitor a directory for new files
./tools/monitor_folder.sh /path/to/directory

# Monitor only for new files (skip existing files)
./tools/monitor_folder.sh /path/to/directory --only-monitor
```

**docker compose :**
```bash
# Monitor a directory
docker compose run --rm -v /path/to/directory:/data/directory cli monitor /data/directory

# Monitor only for new files (skip existing)
docker compose run --rm -v /path/to/directory:/data/directory cli monitor /data/directory --only-monitor
```

**Poetry :**
```bash
# Monitor a directory w/ Poetry env
poetry run python -m cli monitor /path/to/directory
```

### Advanced Options

**./tools/monitor_folder.sh (easiest option, preferred) :**
```bash
./tools/monitor_folder.sh /path/to/directory \
  --host nemesis.example.com:7443 \
  --username your-username \
  --password your-password \
  --only-monitor
```

**docker compose :**
```bash
docker compose run --rm -v /path/to/directory:/data/directory cli monitor /data/directory \
  --host nemesis.example.com:7443 \
  --username your-username \
  --password your-password \
  --project my-project \
  --agent-id my-agent \
  --workers 5 \
  --only-monitor \
  --debug
```

### Options Reference

| Option          | Default                   | Description                                    |
| --------------- | ------------------------- | ---------------------------------------------- |
| `--host`        | `0.0.0.0:7443`            | Nemesis host and port                          |
| `--username`    | `n`                       | Basic auth username                            |
| `--password`    | `n`                       | Basic auth password                            |
| `--project`     | `assess-test`             | Project name for metadata                      |
| `--agent-id`    | `monitor<user>@<host>`    | Agent ID for metadata                          |
| `--workers`     | `10`                      | Number of upload threads for initial submission |
| `--only-monitor`| `false`                   | Skip existing files, only monitor for new ones |
| `--debug`       | `false`                   | Enable debug logging                           |


## Mythic Connector

Synchronize data between Mythic C2 and Nemesis, including callbacks, tasks, and file downloads.

The `./tools/mythic_connect.sh` script wraps the docker compose syntax automatically.

### Configuration

Create a configuration file (e.g., `settings_mythic.yaml`):

```yaml
mythic:
  url: "https://mythic.local:7443"

  # Password authentication
  credential:
    username: "mythic_user"
    password: "mythic_password"

  # OR Token authentication
  # credential:
  #   token: "mythic_api_token"

nemesis:
  url: "https://nemesis.local:7443/"
  credential:
    username: "nemesis_user"
    password: "nemesis_password"
  expiration_days: 100  # File retention period
  max_file_size: 1000000000  # 1GB limit

db:
  path: "mythic_sync.db"  # Local sync state database

networking:
  timeout_sec: 30
  validate_https_certs: true
```

### Usage

**./tools/mythic_connect.sh (easiest option, preferred) :**
```bash
./tools/mythic_connect.sh /path/to/settings_mythic.yaml
```

**docker compose :**
```bash
# Run with mounted config file
docker compose run --rm \
  -v /path/to/settings_mythic.yaml:/config/settings_mythic.yaml \
  cli connect-mythic -c /config/settings_mythic.yaml

# Show example configuration
docker compose run --rm cli connect-mythic --showconfig

# Enable debug logging
docker compose run --rm \
  -v /path/to/settings_mythic.yaml:/config/settings_mythic.yaml \
  cli connect-mythic -c /config/settings_mythic.yaml --debug
```

### What Gets Synchronized

- **Callbacks**: Agent information and metadata
- **Tasks**: Command execution history
- **File Downloads**: Agent-collected files
- **Artifacts**: IOCs and observables
- **Screenshots**: Visual captures from agents

## Outflank Connector

Ingest data from Outflank Stage1 C2 into Nemesis.

### Configuration

Create a configuration file (e.g., `settings_outflank.yaml`):

```yaml
cache_db_path: "/tmp/nemesis_connectors"
conn_timeout_sec: 5
validate_https_certs: true

nemesis:
  url: "https://nemesis.example.com"
  credential:
    username: "connector_bot"
    password: "connector_password"
  expiration_days: 100
  max_file_size: 1000000000

outflank:
  - url: "https://stage1.example.com"
    credential:
      username: "nemesis_bot"
      password: "outflank_password"

    # Optional: Read from disk instead of API
    # outflank_upload_path: "/opt/stage1/"
```

### Usage

```bash
# Run with mounted config file
docker compose run --rm \
  -v /path/to/settings_outflank.yaml:/config/settings_outflank.yaml \
  cli connect-outflank -c /config/settings_outflank.yaml

# Show example configuration
docker compose run --rm cli connect-outflank --showconfig

# Enable debug logging
docker compose run --rm \
  -v /path/to/settings_outflank.yaml:/config/settings_outflank.yaml \
  cli connect-outflank -c /config/settings_outflank.yaml --debug
```

## Common Docker Patterns

### Volume Mounting

```bash
# Mount single file
-v /host/path/file.txt:/container/path/file.txt

# Mount directory
-v /host/path/directory:/container/path/directory

# Mount config file
-v /host/path/config.yaml:/config/config.yaml
```

### Network Access

Use `--network host` if the CLI needs to access services on the host network:

```bash
docker compose run --rm --network host \
  -v /path/to/config.yaml:/config/config.yaml \
  cli connect-mythic -c /config/config.yaml
```

### Environment Variables

Pass environment variables for dynamic configuration:

```bash
docker compose run --rm \
  -e NEMESIS_HOST=nemesis.example.com \
  -e NEMESIS_USER=myuser \
  cli submit /data/file --host $NEMESIS_HOST --username $NEMESIS_USER
```

## Troubleshooting

### Common Issues

1. **Connection refused**: Check that Nemesis/Mythic/Outflank services are running and accessible
2. **Permission denied**: Ensure Docker has permission to access mounted files/directories
3. **SSL certificate errors**: Set `validate_https_certs: false` in config for self-signed certificates
4. **Large file uploads**: Adjust `max_file_size` and `--workers` for better performance

### Debug Mode

Enable debug logging for detailed information:

```bash
# For connectors
cli connect-mythic -c config.yaml --debug

# For file submission
cli submit /data/files --debug
```

### Logs

View container logs:

```bash
# View logs from running container
docker compose logs cli

# Follow logs in real-time
docker compose logs -f cli
```

## Performance Tuning

### File Submission

- Increase `--workers` for parallel uploads (default: 10)
- Use `--recursive` efficiently by targeting specific directories
- Monitor network bandwidth and adjust workers accordingly

### Connectors

- Adjust `timeout_sec` based on network conditions
- Use `outflank_upload_path` for better performance with Outflank
- Monitor database size and clean up periodically
