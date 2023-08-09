 # File Information
Date type: `file_information`

## Overview
Information about a specific file system resource. Note that `file_info` is more specialized than the `path_list` submission which may include information about non-file system resources (ex. registry paths). The path must be in a UNC, file system, or mapped path format. File system and mapped paths must be absolute and use forward slashes for separators (e.g. `/`).  Paths are expected to be canonicalized but there is no verification of this. Submission parameters may accommodate files from most operating systems. The only submission parameters that are required is the file path and type. Note that all date time parameters in ODRs including for the modified, access, and creation times for Windows files are expected to be in UTC.

| Parameters        | Format   | Description                               |
| ----------------- | -------- | ----------------------------------------- |
| path              | string   | Case sensitive file path                  |
| type              | string   | Case insensitive full name of file type   |
| size              | long     | Size in bytes                             |
| creation_time     | datetime | The file the file was created             |
| access_time       | datetime | The last time the file was accessed       |
| modification_time | datetime | The last time the file was modified       |
| access_mode       | int      | *nix permission number                    |
| group             | string   | *nix case sensitive file group membership |
| id                | string   | *nix string for an inode or file id       |
| owner             | string   | Case sensitive owner (*nix and Windows)   |
| sddl              | string   | Case sensitive Windows permission string  |
| version_info      | string   | Windows VersionInfo as a single string    |

### File Types

The current supported file types:

| Type   | Description            |
| ------ | ---------------------- |
| file   | An actual file on disk |
| folder | A folder on disk       |
| share  | A remote network share |

## Protobuf Definition

**FileInformationIngestionMessage** and **FileInformationIngestion** in *nemesis.proto*

## Examples

JSON:
```json
{
    "data": [
        ...
        {
            "path": "//server/C$/Temp/out.txt",
            "size": "42",
            "type": "file",
            ...
        },
        ...
    ]
    "metadata": {
        "agent_id": "339429212",
        "agent_type": "beacon",
        "automated": 1,
        "data_type": "file_information",
        "expiration": "2023-08-01T22:51:35",
        "source": "DC",
        "project": "ASSESS-X",
        "timestamp": "2022-08-01T22:51:35"
    }
}
```