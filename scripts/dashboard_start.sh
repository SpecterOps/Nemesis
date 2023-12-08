#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR/../
skaffold dev -m dashboard --port-forward
poetry run -C ../cmd/dashboard/dashboard streamlit run Nemesis.py
