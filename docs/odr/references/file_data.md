# File Data
Date type: `file_data`

## Overview
The content of a specific file system resource. The path must be in a UNC, file system, or mapped path format. File system and mapped paths must be absolute and use forward slashes for separators (e.g. `/`).  Paths are expected to be canonicalized but there is no verification of this.

The `object_id` field is retrieved by first uploading the file to the `./file` endpoint, which saves the file to the backend storage and returns a `{"object_id": "X..."}` JSON structure.

| Parameters | Format | Description                                 |
| ---------- | ------ | ------------------------------------------- |
| path       | string | The original full file path                 |
| size       | long   | Size of the file, in bytes                  |
| object_id  | UUID   | The UUID returned on file upload to Nemesis |

## Protobuf Definition

**FileDataIngestionMessage** and **FileDataIngestion** in *nemesis.proto*

## Examples
```json
{
    "data": [
        ...
        {
            "path": "//server/C$/Temp/out.txt",
            "size": 42,
            "object_id": "2f0a4f7a-6b97-4869-a8b6-d7df3c9f5124"
        },
        ...
    ]
    "metadata": {
        "agent_id": "339429212",
        "agent_type": "beacon",
        "automated": 1,
        "data_type": "file_data",
        "expiration": "2023-08-01T22:51:35",
        "source": "DC",
        "project": "ASSESS-X",
        "timestamp": "2022-08-01T22:51:35"
    }
}
```