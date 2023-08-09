#/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# run the program, passing in arguments passed to the script
poetry run -C "${SCRIPT_DIR}/../cmd/enrichment" python -m enrichment.cli.submit_to_nemesis "$@"
