#!/bin/bash

if ! test -f submit_to_nemesis.yaml; then
    # first download the submit config if it doesn't exist
    wget https://raw.githubusercontent.com/SpecterOps/Nemesis/e8a75a5adac1ca93d3ddc5f144306071c302064c/cmd/enrichment/enrichment/cli/submit_to_nemesis/submit_to_nemesis.yaml
fi

echo -e "\nEdit './submit_to_nemesis.yaml' to reflect your Nemesis instance."
echo -e "      NOTE: localhost/127.0.0.1 will not work for the Nemesis URL within the container.\n"
echo -e "Files copied into $PWD/submit/ will be submitted to Nemesis.\n"

docker run -it -v "$PWD/submit_to_nemesis.yaml":/config.yaml -v "$PWD/submit/":/submit/ specterops/nemesis-submit
