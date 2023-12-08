#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pushd "$SCRIPT_DIR/../cmd/enrichment" > /dev/null

# Check if the virtualenv exists and install poetry packages if not
if [ ! -d ".venv" ]; then
    poetry install
fi

popd > /dev/null

# run the program, passing in arguments passed to the script
poetry run -C "${SCRIPT_DIR}/../cmd/enrichment" python -m enrichment.cli.submit_to_nemesis "$@"
