# Nemesis CLI

The Nemesis CLI provides tools for interacting with the Nemesis platform, including file submission and data synchronization with external C2 frameworks.

## Overview

The CLI supports four main operations:

- **File Submission**: Upload files directly to Nemesis for processing
- **Folder Monitoring**: Monitor a folder for new files and submit them to Nemesis for processing
- **Mythic Connector**: Synchronize data between Mythic C2 and Nemesis
- **Outflank Connector**: Ingest data from Outflank Stage1 C2 into Nemesis

## Installation & Setup
You can run the Nemesis CLI via its published docker image or by building/running the Python project locally. In general, the easiest way to use it is with the docker helper scripts found in the `./tools/` folder that are detailed below.

### Docker Method (Recommended)

You can pull and run the latest version of the Nemesis CLI docker image with the following command:
```bash
docker run ghcr.io/specterops/nemesis/cli
```
You can then manually invoke it using `docker run`. For example, the following mounts a folder into the container and submits a file:
```bash
docker run --rm --network host -v /tmp/:/data ghcr.io/specterops/nemesis/cli submit /data -r
```

The helper scripts `./tools/submit.sh`, `./tools/monitor_folder.sh`, and `./tools/mythic_connect.sh` wrap the required docker syntax for ease of use and are highly recommended.

If you want to manually build the docker images, see [the Nemesis CLI project's README](https://github.com/SpecterOps/Nemesis/blob/main/projects/cli/README.md).

### Local Method (Development)
To use the Nemesis CLI locally or for development, install at least Python 3.12.8 and [install uv](https://docs.astral.sh/uv/getting-started/installation/). Then, run the following:

```bash
cd Nemesis/projects/cli
uv sync
uv run python -m cli <command>
```

## HTTPS Certificate Verification

The CLI and all connectors verify HTTPS certificates by default. Nemesis ships with a self-signed certificate
(`infra/traefik/certs/server.crt`), so unless you have replaced it with a trusted certificate you must explicitly opt out
of verification using either:

- the `--ignore-cert-errors` flag (available on `submit`, `monitor`, `connect-mythic`, `connect-outflank`, and
  `connect-cobaltstrike`), or
- the `NEMESIS_IGNORE_CERT_ERRORS=1` environment variable. The `./tools/*.sh` helper scripts forward this variable into
  the container.

```bash
./tools/submit.sh /path/to/file --ignore-cert-errors

# or
export NEMESIS_IGNORE_CERT_ERRORS=1
./tools/submit.sh /path/to/file
```

For connectors, `--ignore-cert-errors` overrides the config file's `validate_https_certs` setting, which applies to both
the Nemesis and C2 connections. The Mythic connector also honors
`MYTHIC_SYNC_NETWORKING__VALIDATE_HTTPS_CERTS=false`.

**Disabling verification is insecure:** anyone positioned on the network path can intercept the Basic-auth credentials
and every uploaded file. Prefer installing a trusted certificate on Nemesis.

## File Submission

Submit files to Nemesis for processing and enrichment.

The `./tools/submit.sh` script wraps the docker syntax automatically.

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

# Submit directory, changing the Nemesis server (default is localhost) and credentials (default is n:n)
./tools/submit.sh /path/to/directory/ \
  --host nemesis.example.com:7443 \
  --username your-username \
  --password your-password

# Submit files customizing various options and use debug logging
./tools/submit.sh submit /path/file1 /path/file2  \
  --host nemesis.example.com:7443 \
  --username your-username \
  --password your-password \
  --project my-project \
  --source host://HOST1 \
  --agent-id my-agent \
  --workers 5 \
  --recursive \
  --debug
```

**Local (uv) :**
```bash
# Submit a single file w/ local env
cd Nemesis/projects/cli
uv run python -m cli submit /data/file
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
  --source TEXT          Source name for metadata (e.g., 'host://HOST1')
  --agent-id TEXT        Agent ID for metadata  [default:
                         submitunknown_user@docker-desktop]
  -f, --file FILE        Path to single file to submit (alternative to PATHS
                         for backwards compatibility)
  --help                 Show this message and exit.
```

| Option        | Default               | Description                                                             |
| ------------- | --------------------- | ----------------------------------------------------------------------- |
| `--host`      | `0.0.0.0:7443`        | Nemesis host and port                                                   |
| `--recursive` | `false`               | Process subdirectories                                                  |
| `--workers`   | `10`                  | Number of upload threads                                                |
| `--username`  | `n`                   | Basic auth username                                                     |
| `--password`  | `n`                   | Basic auth password                                                     |
| `--project`   | `assess-test`         | Project name for metadata                                               |
| `--source`    |                       | Source name (e.g., 'host://HOST1' or 'https://domain.com') for metadata |
| `--agent-id`  | `submit<user>@<host>` | Agent ID for metadata                                                   |
| `--debug`     | `false`               | Enable debug logging                                                    |
| `--ignore-cert-errors` | `false`      | Skip HTTPS certificate verification (env: `NEMESIS_IGNORE_CERT_ERRORS`) |

## Folder Monitoring

Monitor a folder for new files and automatically submit them to Nemesis for processing. This includes both existing files (optional) and any new files added to the folder while monitoring is active.

The `./tools/monitor_folder.sh` script wraps the docker syntax automatically.

### Basic Usage

**./tools/monitor_folder.sh (easiest option, preferred) :**
```bash
# Monitor a directory for new files
./tools/monitor_folder.sh /path/to/directory

# Monitor only for new files (skip existing files)
./tools/monitor_folder.sh /path/to/directory --only-monitor

# Monitor a directory upload files to a Nemesis server
./tools/monitor_folder.sh /path/to/directory \
  --host nemesis.example.com:7443 \
  --username your-username \
  --password your-password \
```

**docker:**
```bash
# Monitor a directory
docker run \
  --rm -ti \
  --network host \
  -v /path/to/directory:/data/directory \
  ghcr.io/specterops/nemesis/cli \
  monitor /data/directory

# Monitor only for new files (skip existing)
docker run \
  --rm -ti \
  --network host \
  -v /path/to/directory:/data/directory \
  ghcr.io/specterops/nemesis/cli \
  monitor /data/directory --only-monitor

# Monitor a directory with advanced configuration
docker run \
  --rm -ti \
  --network host \
  -v /path/to/directory:/data/directory \
  ghcr.io/specterops/nemesis/cli \
  monitor /data/directory \
  --host nemesis.example.com:7443 \
  --username your-username \
  --password your-password \
  --project my-project \
  --source host://HOST1 \
  --agent-id my-agent \
  --workers 5  \
  --debug
```

**Local (uv) :**
```bash
# Monitor a directory w/ local env
cd Nemesis/projects/cli
uv sync
uv run python -m cli monitor /path/to/directory
```

### Options Reference

| Option           | Default                | Description                                                             |
| ---------------- | ---------------------- | ----------------------------------------------------------------------- |
| `--host`         | `0.0.0.0:7443`         | Nemesis host and port                                                   |
| `--username`     | `n`                    | Basic auth username                                                     |
| `--password`     | `n`                    | Basic auth password                                                     |
| `--project`      | `assess-test`          | Project name for metadata                                               |
| `--source`       |                        | Source name (e.g., 'host://HOST1' or 'https://domain.com') for metadata |
| `--agent-id`     | `monitor<user>@<host>` | Agent ID for metadata                                                   |
| `--workers`      | `10`                   | Number of upload threads for initial submission                         |
| `--only-monitor` | `false`                | Skip existing files, only monitor for new ones                          |
| `--debug`        | `false`                | Enable debug logging                                                    |
| `--ignore-cert-errors` | `false`          | Skip HTTPS certificate verification (env: `NEMESIS_IGNORE_CERT_ERRORS`) |


## Mythic Connector

Synchronize data between Mythic C2 and Nemesis, including callbacks, tasks, and file downloads.

The `./tools/mythic_connect.sh` script wraps the docker syntax automatically.

### Configuration

Create a configuration file (e.g., `settings_mythic.yaml`):

```yaml
mythic:
  url: "https://mythic.local:7443"
  agent_id: "mythic"  # Identifies this Mythic instance on uploaded files

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

# Optional: connector state directory (default: $XDG_STATE_HOME/nemesis/connectors
# or ~/.local/state/nemesis/connectors)
# db:
#   path: "~/.local/state/nemesis/connectors"

networking:
  timeout_sec: 30
  validate_https_certs: true  # Verifies Mythic's certificate for logins, GraphQL, websockets and downloads

sync:
  pending_give_up_days: 7  # Stop waiting for a download with no new chunks for this many days
  max_pending_subscriptions: 10  # Websockets watching unfinished downloads (100 each); the rest are polled every 30 s
```

The connector keeps its discovery cursor and which files it has uploaded in a LevelDB database under
`db.path`. It logs the exact path at startup. Keep this directory between runs, or every Mythic file is
uploaded again (see [Connector state in Docker](#connector-state-in-docker)).

It syncs agent downloads and screenshots from every operation the Mythic user belongs to. Screenshots and
downloads that Mythic stores without a full remote path are uploaded as `/<host>/screenshots/<name>` and
`<name>` respectively. Collection time comes from Mythic, and files expire `nemesis.expiration_days` later.
Mythic restarts and proxy errors are retried with backoff; rejected credentials or permissions stop the
connector.

### Usage

**./tools/mythic_connect.sh (easiest option, preferred) :**
```bash
./tools/mythic_connect.sh /path/to/settings_mythic.yaml
```

The script keeps connector state in the `nemesis-connector-state` Docker volume (set
`NEMESIS_CONNECTOR_STATE_VOLUME` to use another), overriding any `db.path` in the config file.

**docker :**
```bash
# Run with mounted config file
docker run \
  --rm -ti \
  -v nemesis-connector-state:/root/.local/state \
  -v /path/to/settings_mythic.yaml:/config/settings_mythic.yaml \
  ghcr.io/specterops/nemesis/cli \
  connect-mythic -c /config/settings_mythic.yaml

# Show example configuration
docker run --rm ghcr.io/specterops/nemesis/cli connect-mythic --showconfig

# Enable debug logging
docker run --rm -ti \
  -v nemesis-connector-state:/root/.local/state \
  -v /path/to/settings_mythic.yaml:/config/settings_mythic.yaml \
  ghcr.io/specterops/nemesis/cli \
  connect-mythic -c /config/settings_mythic.yaml --debug
```

### What Gets Synchronized

- **File Downloads**: Agent-collected files
- **Screenshots**: Visual captures from agents

## Cobalt Strike Connector

Ingest data from Cobalt Strike into Nemesis.

### Requirements

- The Cobalt Strike API Server should be running. For information on starting the REST API server, see [Starting the REST API Server](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_starting-rest-server.htm).
- Cobalt Strike should be installed and configured.
- Cobalt Strike should be properly licensed

### Configuration

Create a configuration file (e.g., `settings_cobaltstrike.yaml`):

```yaml
cache_db_path: "~/.local/state/nemesis/connectors"
conn_timeout_sec: 5
validate_https_certs: true

nemesis:
  url: "https://nemesis.example.com"
  credential:
    username: "connector_bot"
    password: "connector_password"
  expiration_days: 100
  max_file_size: 1000000000

cobaltstrike:
  - url: "https://cobaltstrike.example.com:50443"
    credential:
      username: "nemesis_bot"
      password: "cobaltstrike_password"

    project: "project name"
    agent_id: "cobaltstrike"  # Identifies this Cobalt Strike instance on uploaded files
    poll_interval_sec: 3
```

### Usage

```bash
# Run with mounted config file
docker run \
  --rm -ti \
  -v nemesis-connector-state:/root/.local/state \
  -v /path/to/settings_cobaltstrike.yaml:/config/settings_cobaltstrike.yaml \
  ghcr.io/specterops/nemesis/cli \
  connect-cobaltstrike -c /config/settings_cobaltstrike.yaml

# Show example configuration
docker run --rm ghcr.io/specterops/nemesis/cli connect-cobaltstrike --showconfig

# Enable debug logging
docker run --rm \
  -v nemesis-connector-state:/root/.local/state \
  -v /path/to/settings_cobaltstrike.yaml:/config/settings_cobaltstrike.yaml \
  ghcr.io/specterops/nemesis/cli \
  connect-cobaltstrike -c /config/settings_cobaltstrike.yaml --debug
```

## Outflank Connector

Ingest data from Outflank Stage1 C2 into Nemesis.

### Configuration

Create a configuration file (e.g., `settings_outflank.yaml`):

```yaml
cache_db_path: "~/.local/state/nemesis/connectors"
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
    agent_id: "stage1"  # Identifies this Outflank instance on uploaded files

    # Optional: Read from disk instead of API
    # downloads_dir_path: "/opt/stage1/shared/downloads"
```

### Usage

```bash
# Run with mounted config file
docker run \
  --rm -ti \
  -v nemesis-connector-state:/root/.local/state \
  -v /path/to/settings_outflank.yaml:/config/settings_outflank.yaml \
  ghcr.io/specterops/nemesis/cli \
  connect-outflank -c /config/settings_outflank.yaml

# Show example configuration
docker run --rm ghcr.io/specterops/nemesis/cli connect-outflank --showconfig

# Enable debug logging
docker run --rm \
  -v nemesis-connector-state:/root/.local/state \
  -v /path/to/settings_outflank.yaml:/config/settings_outflank.yaml \
  ghcr.io/specterops/nemesis/cli \
  connect-outflank -c /config/settings_outflank.yaml --debug
```

## Connector state in Docker

The Mythic, Cobalt Strike and Outflank connectors record which downloads they have already uploaded. By
default this lives in `~/.local/state/nemesis/connectors` (or `$XDG_STATE_HOME/nemesis/connectors`), set by
`db.path` for Mythic and `cache_db_path` for the others. Each connector logs the exact path at startup, and
`connect-* --help` shows the default.

A `docker run --rm` container loses that directory when it exits, so the examples above mount the named
volume `nemesis-connector-state` at `/root/.local/state`. Without it, every restart uploads every file again.
If you set `db.path` or `cache_db_path` in the config file, point it inside the mounted volume. Dry runs
(`--dry-run`) use a temporary directory and don't need the volume.

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
docker run --rm --network host \
  -v /path/to/config.yaml:/config/config.yaml \
  ghcr.io/specterops/nemesis/cli \
  connect-mythic -c /config/config.yaml
```

### Environment Variables

Pass environment variables for dynamic configuration:

```bash
docker run --rm \
  -e NEMESIS_HOST=nemesis.example.com \
  -e NEMESIS_USER=myuser \
  ghcr.io/specterops/nemesis/cli \
  submit /data/file --host $NEMESIS_HOST --username $NEMESIS_USER
```

## Troubleshooting

### Common Issues

1. **Connection refused**: Check that Nemesis/Mythic/Outflank services are running and accessible
2. **Permission denied**: Ensure Docker has permission to access mounted files/directories
3. **SSL certificate errors**: For self-signed certificates, pass `--ignore-cert-errors` or set `NEMESIS_IGNORE_CERT_ERRORS=1` (connectors can also set `validate_https_certs: false` in their config). See [HTTPS Certificate Verification](#https-certificate-verification)
4. **Large file uploads**: Adjust `max_file_size` and `--workers` for better performance

### Debug Mode

Enable debug logging for detailed information:

```bash
# For connectors
cli connect-mythic -c config.yaml --debug

# For file submission
cli submit /data/files --debug
```

## Performance Tuning

### File Submission

- Increase `--workers` for parallel uploads (default: 10)
- Use `--recursive` efficiently by targeting specific directories
- Monitor network bandwidth and adjust workers accordingly

### Connectors

- Adjust `timeout_sec` based on network conditions
- Use `downloads_dir_path` for better performance with Outflank

