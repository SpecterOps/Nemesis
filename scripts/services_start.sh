#/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR/../

# If any additional args are passed, start only the services module (no enrichment)
if [ $# -gt 0 ]; then
    skaffold --update-check=false --interactive=false dev -m services -m dashboard --port-forward
else
    skaffold --update-check=false --interactive=false dev -m services -m dashboard -m enrichment --port-forward
fi
