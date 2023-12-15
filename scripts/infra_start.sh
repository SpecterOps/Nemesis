#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR/../
skaffold --update-check=false --interactive=false dev -m infra-core -m infra-nemesis -m monitoring --port-forward=user -p dev
