#!/bin/bash

PROTOBUF_DIR="sliver/protobuf"
LIB_OUT="sliver_service/pb"

if [ -f "sliver" ]; then
    echo "Sliver path already exists"
else
    git clone https://github.com/BishopFox/sliver
fi

if [ -f $LIB_OUT ]; then
    echo "PBs path already exists"
else
    mkdir $LIB_OUT
fi

for dir in $(find $PROTOBUF_DIR -type d); do
    python3 -m grpc_tools.protoc --proto_path=$PROTOBUF_DIR --python_out=$LIB_OUT --grpc_python_out=$LIB_OUT $dir/*.proto
done