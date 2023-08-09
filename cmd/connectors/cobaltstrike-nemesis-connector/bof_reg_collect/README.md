# Building

1. Install mingw with `$ sudo apt-get install mingw-w64` if it is not already installed.

2. Build the collector with `$ make`

# Usage

1. Run the registry collector to get registry keys
```
bof_reg_collect <HKCR|HKCU|HKLM|HKU|HKCC> <path>
```

2. Download file in downloads folder

3. Parse output with `nemesis_reg_collect_parser.py`

```
python3 nemesis_reg_collect_parser.py <input.txt> <output.json>
```

## Example

```
reg_collect HKLM SYSTEM\CurrentControlSet\Services\ACPI
```

```
$ python3 ./nemesis_reg_collect_parser.py ~/test.bin /tmp/test.json
$ cat /tmp/test.json
[{"type_": 3, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters\\WakeUp", "path_size": 112, "key": "FixedEventMask", "key_size": 28, "value": [32, 5], "value_size": 2}, {"type_": 3, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters\\WakeUp", "path_size": 112, "key": "FixedEventStatus", "key_size": 32, "value": [0, 129], "value_size": 2}, {"type_": 3, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters\\WakeUp", "path_size": 112, "key": "GenericEventMask", "key_size": 32, "value": [8, 0], "value_size": 2}, {"type_": 3, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters\\WakeUp", "path_size": 112, "key": "GenericEventStatus", "key_size": 36, "value": [0, 0], "value_size": 2}, {"type_": 3, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters", "path_size": 98, "key": "WHEAOSCImplemented", "key_size": 36, "value": [0, 0, 0, 0], "value_size": 4}, {"type_": 3, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters", "path_size": 98, "key": "APEIOSCGranted", "key_size": 28, "value": [0, 0, 0, 0], "value_size": 4}, {"type_": 3, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters", "path_size": 98, "key": "CPPCRevisionGranted", "key_size": 38, "value": [0, 0, 0, 0], "value_size": 4}, {"type_": 1, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters", "path_size": 98, "key": "WppRecorder_TraceGuid", "key_size": 42, "value": "{03906a40-cce8-447f-83f4-e2346215db84}\u0000", "value_size": 78}, {"type_": 3, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Parameters", "path_size": 98, "key": "AMLIMaxCTObjs", "key_size": 26, "value": [0, 0, 0, 0], "value_size": 4}, {"type_": 1, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Enum", "path_size": 86, "key": "0", "key_size": 2, "value": "ACPI_HAL\\PNP0C08\\0\u0000", "value_size": 38}, {"type_": 4, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Enum", "path_size": 86, "key": "Count", "key_size": 10, "value": 1, "value_size": 0}, {"type_": 4, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI\\Enum", "path_size": 86, "key": "NextInstance", "key_size": 24, "value": 1, "value_size": 0}, {"type_": 2, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI", "path_size": 76, "key": "ImagePath", "key_size": 18, "value": "System32\\drivers\\ACPI.sys\u0000\u0000", "value_size": 54}, {"type_": 4, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI", "path_size": 76, "key": "Type", "key_size": 8, "value": 1, "value_size": 0}, {"type_": 4, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI", "path_size": 76, "key": "Start", "key_size": 10, "value": 0, "value_size": 0}, {"type_": 4, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI", "path_size": 76, "key": "ErrorControl", "key_size": 24, "value": 3, "value_size": 0}, {"type_": 1, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI", "path_size": 76, "key": "DisplayName", "key_size": 22, "value": "@acpi.inf,%ACPI.SvcDesc%;Microsoft ACPI Driver\u0000", "value_size": 94}, {"type_": 7, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI", "path_size": 76, "key": "Owners", "key_size": 12, "value": ["acpi.inf"], "value_size": 20}, {"type_": 4, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI", "path_size": 76, "key": "Tag", "key_size": 6, "value": 2, "value_size": 0}, {"type_": 1, "path": "SYSTEM\\CurrentControlSet\\Services\\ACPI", "path_size": 76, "key": "Group", "key_size": 10, "value": "Core\u0000", "value_size": 10}]
```

# TODO
- Return what path was queried so that data is known by Nemesis
- File type integrated with Nemesis
- Compress file blob
- Parser could be rewritten as a parser combinator
- Check for memory leaks
- Make recursive query optional
- Split functionality
    - Key existance: Check if key exists
    - Key enumeration: only return keys and don't return values
    - SDDL enumeration: Check SDDL along with key/value