#!/bin/bash
# Wrapper script to submit a job to the Nemesis CLI using Docker
# Added into the tools/ dir for convenience (near project root)
#
# Each file or directory argument is bind-mounted read-only at its real absolute path inside the
# container, so Nemesis records the path it has on this machine (e.g. /home/op/loot/x.txt rather than
# /data/x.txt), and two arguments with the same basename no longer collide. Paths that would shadow
# the container's own files (/usr, /src, ...) are mounted under a unique /nemesis-submit/<n>/ directory instead, with a warning.
#
# Set NEMESIS_PASSWORD in the environment to pass it to the container with `-e` instead of on the
# command line (only takes effect with a CLI version that reads NEMESIS_PASSWORD).
#
# A CA file for Nemesis's certificate, given with --ca-file or NEMESIS_CA_FILE, is mounted read-only
# into the container and passed on with its container path.

# Default image, can be overridden with NEMESIS_CLI_IMAGE env var
NEMESIS_CLI_IMAGE="${NEMESIS_CLI_IMAGE:-ghcr.io/specterops/nemesis/cli:latest}"

DOCKER_ARGS=()
SUBMIT_ARGS=()
CLI_OPTIONS=()
MOUNT_COUNT=0
MOUNTED_SOURCES=()  # local absolute paths already mounted (bash 3 compatible: no associative arrays)
MOUNTED_TARGETS=()  # ...and where each is mounted in the container

# Options that don't take a value (flags only)
OPTIONS_WITHOUT_VALUES=("--debug" "--recursive" "-r" "--container" "--help")
# Options whose value is a local file that must be mounted
FILE_VALUE_OPTIONS=("--filters" "-f" "--file" "--ca-file")
# Where paths that can't keep their real location are mounted
FALLBACK_ROOT=/nemesis-submit
# Container trees a mount must not shadow (the CLI image lives in /src and /venv)
RESERVED_PREFIXES=(/bin /dev /etc /lib /lib32 /lib64 /libx32 /proc /sbin /src /sys /usr /venv "$FALLBACK_ROOT")
# Top-level directories that may be mounted into (e.g. /tmp/loot/x) but not replaced as a whole
RESERVED_EXACT=(/ /boot /home /media /mnt /opt /root /run /srv /tmp /var)

in_list() { # in_list VALUE ITEM...
  local value=$1 item
  shift
  for item in "$@"; do
    [[ "$value" == "$item" ]] && return 0
  done
  return 1
}

# Quote one field of a docker --mount value (CSV: wrap in double quotes, double any quote inside).
csv_field() {
  printf '"%s"' "${1//\"/\"\"}"
}

# Print the container path for local ABS_PATH: the same path when that is safe, else /nemesis-submit/<n>/<basename>.
container_path_for() {
  local abs_path=$1 prefix
  if in_list "$abs_path" "${RESERVED_EXACT[@]}"; then
    echo "${FALLBACK_ROOT}/${MOUNT_COUNT}/$(basename "$abs_path")"
    return
  fi
  for prefix in "${RESERVED_PREFIXES[@]}"; do
    if [[ "$abs_path" == "$prefix" || "$abs_path" == "$prefix"/* ]]; then
      echo "${FALLBACK_ROOT}/${MOUNT_COUNT}/$(basename "$abs_path")"
      return
    fi
  done
  echo "$abs_path"
}

# Mount local path $1 read-only and set MOUNTED_PATH to where the container sees it.
mount_path() {
  local abs_path
  abs_path="$(realpath "$1")"
  # The same path given twice: reuse its mount (docker refuses duplicate mount points)
  local n
  for ((n = 0; n < ${#MOUNTED_SOURCES[@]}; n++)); do
    if [[ "${MOUNTED_SOURCES[$n]}" == "$abs_path" ]]; then
      MOUNTED_PATH="${MOUNTED_TARGETS[$n]}"
      return
    fi
  done
  MOUNT_COUNT=$((MOUNT_COUNT + 1))
  MOUNTED_PATH="$(container_path_for "$abs_path")"
  if [[ "$MOUNTED_PATH" != "$abs_path" ]]; then
    echo "Warning: '$abs_path' is mounted at '$MOUNTED_PATH' in the container; Nemesis will record that path." >&2
  fi
  MOUNTED_SOURCES+=("$abs_path")
  MOUNTED_TARGETS+=("$MOUNTED_PATH")
  # --mount (not -v) so paths containing ':' or ',' work: each field is CSV-quoted
  DOCKER_ARGS+=(--mount "type=bind,$(csv_field "source=$abs_path"),$(csv_field "target=$MOUNTED_PATH"),readonly")
}

args=("$@")
i=0
while [[ $i -lt ${#args[@]} ]]; do
    arg="${args[$i]}"

    if [[ "$arg" == -* ]] && ! in_list "$arg" "${OPTIONS_WITHOUT_VALUES[@]}"; then
        # This option takes a value, so we need to handle both the option and its value
        CLI_OPTIONS+=("$arg")
        i=$((i + 1))
        if [[ $i -lt ${#args[@]} ]]; then
            value="${args[$i]}"
            # Mount files given as option values (e.g. --filters, -f)
            if in_list "$arg" "${FILE_VALUE_OPTIONS[@]}" && [[ -f "$value" ]]; then
                mount_path "$value"
                CLI_OPTIONS+=("$MOUNTED_PATH")
            else
                CLI_OPTIONS+=("$value")
            fi
        fi
    elif [[ "$arg" == -* ]]; then
        # This is a flag (no value needed)
        CLI_OPTIONS+=("$arg")
    elif [[ -e "$arg" ]]; then
        # A file or directory to submit
        mount_path "$arg"
        SUBMIT_ARGS+=("$MOUNTED_PATH")
    else
        # Treat as a regular argument
        CLI_OPTIONS+=("$arg")
    fi

    i=$((i + 1))
done

ENV_ARGS=(-e NEMESIS_IGNORE_CERT_ERRORS)
if [[ -n "${NEMESIS_CA_FILE:-}" ]]; then
    if [[ ! -f "$NEMESIS_CA_FILE" ]]; then
        echo "Error: NEMESIS_CA_FILE is not a file: $NEMESIS_CA_FILE" >&2
        exit 1
    fi
    mount_path "$NEMESIS_CA_FILE"
    ENV_ARGS+=(-e "NEMESIS_CA_FILE=$MOUNTED_PATH")
fi
if [[ -n "${NEMESIS_PASSWORD:-}" ]]; then
    # Passed by name, so the value stays off the docker command line
    ENV_ARGS+=(-e NEMESIS_PASSWORD)
fi

# Run the Docker command
exec docker run --network host --rm "${ENV_ARGS[@]}" "${DOCKER_ARGS[@]}" "$NEMESIS_CLI_IMAGE" \
    submit "${SUBMIT_ARGS[@]}" "${CLI_OPTIONS[@]}"
