 # Named Pip
Date type: `named_pipe`

## Overview
Information about a Windows named pipe.

| Parameters          | Format | Description                              |
| ------------------- | ------ | ---------------------------------------- |
| name                | string | Case sensitive pipe name                 |
| server_process_name | string | Name of the server process               |
| server_process_id   | int    | PID of the server process                |
| server_process_path | string | Path of the server process binary        |
| sddl                | string | Case sensitive Windows permission string |

## Protobuf Definition

**NamedPipeIngestionMessage** and **NamedPipeIngestion** in *nemesis.proto*

## Examples

[named_pipes.json](https://github.com/SpecterOps/Nemesis/blob/main/sample_files/structured/named_pipes.json)
