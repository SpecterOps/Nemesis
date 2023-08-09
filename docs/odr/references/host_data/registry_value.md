# Registry Value
Date type: `registry_value`

## Overview
The key name/type, corresponding value, and SDDL of a registry key.
Key paths be absolute and use forward slashes for separators (e.g. `/`).

The `Value` for the key is stored as a string regardless of the ValueKind.
Specifically, values of type REG_BINARY are stored as base64-encoded strings,
while numeric values are stored as strings as well.

### Message format:

| Parameters | Format            | Description                                             |
|------------|-------------------|---------------------------------------------------------|
| key        | string            | The path for the value, including hive (e.g., HKLM/...) |
| value_name | string            | The name of the value                                   |
| value_kind | RegistryValueKind | The RegistryValueKind enum                              |
| value      | string            | String representation of the registry value.            |
| sddl       | string            | SDDL representation of the ACL for this key             |

### RegistryValueKind:

The RegistryValueKind enum is [defined by Microsoft here](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registryvaluekind?view=net-7.0):

| String       | Int | Description                                                                                                                                           |
|--------------|-----|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| Unknown/None | 0   | An unsupported registry data type.                                                                                                                    |
| String       | 1   | A null-terminated string. This value is equivalent to the Windows API registry data type REG_SZ.                                                      |
| ExpandString | 2   | A null-terminated string that contains unexpanded references to environment variables, such as %PATH%, that are expanded when the value is retrieved. |
| Binary       | 3   | Binary data in any form. This value is equivalent to the Windows API registry data type REG_BINARY.                                                   |
| DWord        | 4   | A 32-bit binary number. This value is equivalent to the Windows API registry data type REG_DWORD.                                                     |
| MultiString  | 7   | An array of null-terminated strings, terminated by two null characters. This value is equivalent to the Windows API registry data type REG_MULTI_SZ.  |
| QWord        | 11  | A 64-bit binary number. This value is equivalent to the Windows API registry data type REG_QWORD.                                                     |

## Protobuf Definition

**RegistryValueIngestionMessage** and **RegistryValueIngestion** in *nemesis.proto*

## Examples
```json
{
    "data": [
        ...
        {
            "key": "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "value_name": "DefaultDomainName",
            "value_kind": 1,
            "value": "THESHIRE"
        },
        ...
    ],
    "metadata": {
        "agent_id": "339429212",
        "agent_type": "beacon",
        "automated": 1,
        "data_type": "registry_value",
        "expiration": "2023-08-01T22:51:35",
        "source": "DC",
        "project": "ASSESS-X",
        "timestamp": "2022-08-01T22:51:35"
    }
}
```