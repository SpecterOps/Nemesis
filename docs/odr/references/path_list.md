 # File Information
Date type: `path_list`

## Overview
Child listings for a specified path. The path must be in a UNC, URI, file system, or mapped path format. File system and mapped paths must be absolute and use forward slashes for separators (e.g. `/`).  Paths are expected to be canonicalized but there is no verification of this. The mapped file format may be used to specify a registry keys as well using PowerShell convention of specifying the hive name as the drive (ex. `HKLM:`).

| Parameters | Format   | Description                  |
| ---------- | -------- | ---------------------------- |
| path       | string   | Case sensitive resource path |
| items      | string[] | Case sensitive child items   |


## Protobuf Definition

**PathListIngestionMessage** and **PathListIngestion** in *nemesis.proto*

## Examples

JSON:
```json
{
    "data": [
        ...
        {
            "path": "C:/",
            "items": [
                "Program Files",
                "Program Files (x86)",
                "Windows",
                ...
            ]
        },
        ...
    ]
    "metadata": {
        "agent_id": "339429212",
        "agent_type": "beacon",
        "automated": 1,
        "data_type": "path_list",
        "expiration": "2023-08-01T22:51:35",
        "source": "DC",
        "project": "ASSESS-X",
        "timestamp": "2022-08-01T22:51:35"
    }
}
```