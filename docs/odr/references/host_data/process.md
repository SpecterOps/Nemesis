# Process(es)
Date type: `process`

## Overview
Information about the currently running processes for the host the agent is running on. Submission parameters may accommodate processes information for most operating systems. The only submission parameter that is required is the process id.

| Parameters        | Format          | Description                                        |
| ----------------- | --------------- | -------------------------------------------------- |
| name              | string          | If known, the name of the process                  |
| command_line      | string          | If known, the full command line that was executed  |
| file_name         | string          | If known, the name of the file that was executed   |
| process_id        | int             | Process ID                                         |
| parent_process_id | int             | Parent process ID                                  |
| arch              | string          | Architecture of the process (e.g., x86, x64, arm)  |
| start_time        | datetime        | Time the process was started, if known             |
| memory            | long            | The amount of memory used by the process, in bytes |
| token             | Token           | Token information for the user (if available)      |


### Token

The Token data type is defined as:
```
message Principal {
  // Security identifier, if known
  string sid = 1;

  // Name of the principal, if known. The format should be the Down-Level Logon Name (e.g., DOMAIN\user)
  string name = 2;
}
message Token {
  message TokenPrivilege {
    // Privilege name (e.g., SeDebugPrivilege)
    string privilege_name = 1;

    // Is the privileged enabled
    bool enabled = 2;
  }
  enum TokenType {
    TOKENTYPE_UNSPECIFIED = 0;
    TOKENTYPE_PRIMARY = 1;
    TOKENTYPE_IMPERSONATION = 2;
  }
  enum ImpersonationLevel {
    IMPERSONATIONLEVEL_UNSPECIFIED = 0;
    IMPERSONATIONLEVEL_ANONYMOUS = 1;
    IMPERSONATIONLEVEL_IDENTIFICATION = 2;
    IMPERSONATIONLEVEL_IMPERSONATION = 3;
    IMPERSONATIONLEVEL_DELEGATION = 4;
  }

  Principal user = 1;

  repeated Principal groups = 2;

  repeated TokenPrivilege privileges = 3;

  TokenType type = 4;

  ImpersonationLevel impersonation_level = 5;

  uint32 session = 6;
}
```

## Protobuf Definition

**ProcessIngestionMessage** and **ProcessIngestion** in *nemesis.proto*

## Examples
```json
{
    "data": [
        ...
        {
            "parent_process_id": "2700",
            "name": "conhost.exe",
            "process_id": "4252",
            "arch": "x64",
            "token": {
                "user": {
                    "name": "BASEIMAGE\\localuser"
                },
            }
        },
        ...
    ],
    "metadata": {
        "agent_id": "339429212",
        "agent_type": "beacon",
        "automated": 1,
        "data_type": "process",
        "expiration": "2023-08-01T22:51:35",
        "source": "DC",
        "project": "ASSESS-X",
        "timestamp": "2022-08-01T22:51:35"
    }
}
```

