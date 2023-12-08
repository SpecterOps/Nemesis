#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pushd "$SCRIPT_DIR/../" > /dev/null

./packages/python/nemesispb/build.sh

popd > /dev/null
