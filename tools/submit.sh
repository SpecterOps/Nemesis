#!/bin/bash
# Wrapper script to submit a job to the Nemesis CLI using Docker
# Added into the tools/ dir for convenience (near project root)

# Default image, can be overridden with NEMESIS_CLI_IMAGE env var
NEMESIS_CLI_IMAGE="${NEMESIS_CLI_IMAGE:-ghcr.io/specterops/nemesis/cli:latest}"

# Parse arguments to handle volume mounting and CLI options
DOCKER_ARGS=""
SUBMIT_ARGS=""
CLI_OPTIONS=""

# Options that don't take a value (flags only)
OPTIONS_WITHOUT_VALUES=("--debug" "--recursive" "-r" "--container" "--help")

i=0
args=("$@")
while [[ $i -lt ${#args[@]} ]]; do
    arg="${args[$i]}"
    
    # Check if this is a flag (no value needed)
    is_flag=false
    for opt in "${OPTIONS_WITHOUT_VALUES[@]}"; do
        if [[ "$arg" == "$opt" ]]; then
            is_flag=true
            break
        fi
    done
    
    if [[ "$arg" == --* || "$arg" == -* ]] && [[ $is_flag == false ]]; then
        # This option takes a value, so we need to handle both the option and its value
        CLI_OPTIONS="$CLI_OPTIONS $arg"
        i=$((i + 1))
        if [[ $i -lt ${#args[@]} ]]; then
            value="${args[$i]}"
            
            # Special handling for --filters option - mount the file if it exists
            if [[ "$arg" == "--filters" && -f "$value" ]]; then
                ABS_PATH=$(realpath "$value")
                DOCKER_ARGS="$DOCKER_ARGS -v $ABS_PATH:/data/$(basename "$ABS_PATH")"
                CLI_OPTIONS="$CLI_OPTIONS /data/$(basename "$ABS_PATH")"
            else
                CLI_OPTIONS="$CLI_OPTIONS $value"
            fi
        fi
    elif [[ "$arg" == --* || "$arg" == -* ]]; then
        # This is a flag (no value needed)
        CLI_OPTIONS="$CLI_OPTIONS $arg"
    elif [[ -f "$arg" ]]; then
        # It's a file
        ABS_PATH=$(realpath "$arg")
        DOCKER_ARGS="$DOCKER_ARGS -v $ABS_PATH:/data/$(basename "$ABS_PATH")"
        SUBMIT_ARGS="$SUBMIT_ARGS /data/$(basename "$ABS_PATH")"
    elif [[ -d "$arg" ]]; then
        # It's a directory
        ABS_PATH=$(realpath "$arg")
        DOCKER_ARGS="$DOCKER_ARGS -v $ABS_PATH:/data/$(basename "$ABS_PATH")"
        SUBMIT_ARGS="$SUBMIT_ARGS /data/$(basename "$ABS_PATH")"
    else
        # Treat as a regular argument
        CLI_OPTIONS="$CLI_OPTIONS $arg"
    fi
    
    i=$((i + 1))
done

# Run the Docker command
docker run --network host --rm $DOCKER_ARGS "$NEMESIS_CLI_IMAGE" submit $SUBMIT_ARGS $CLI_OPTIONS