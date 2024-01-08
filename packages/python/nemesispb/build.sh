#!/bin/bash

SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

pushd $SCRIPTPATH > /dev/null

if [[ -z "${VIRTUAL_ENV}" ]]; then
    echo "[*] Setting up Poetry virtualenv..."
    poetry install
    poetry run "$SCRIPT"
else
    echo "[*] Building protobufs..."
    protoc --experimental_allow_proto3_optional --python_out=./nemesispb/ --mypy_out=./nemesispb/ -I../../protobufs/ ../../protobufs/*.proto
    echo "[+] Python protobufs built!"
fi

popd > /dev/null
