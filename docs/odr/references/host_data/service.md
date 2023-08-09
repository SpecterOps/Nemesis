 # Service
Date type: `service`

## Overview
Information about a Windows service.

| Parameters      | Format | Description                                                            |
| --------------- | ------ | ---------------------------------------------------------------------- |
| name            | string | Case sensitive service name                                            |
| display_name    | string | Case sensitive service display name                                    |
| description     | string | Case sensitive sservice description                                    |
| start_name      | string | Case sensitive username the service starts as                          |
| state           | string | Case insensitive state of the service (running, stopped, etc.)         |
| start_mode      | string | Case insensitive start mode of the service (automatic, disabled, etc.) |
| type            | string | Case insensitive type of the service                                   |
| service_command | string | Case sensitive binary path of the serbice binary + any arguments       |
| service_dll     | string | Case sensitive file path of the service DLL being loaded into SVCHOST  |
| service_sddl    | string | Case sensitive Windows permission string                               |

### State

The current supported state values:

| Value           | Description                      |
| --------------- | -------------------------------- |
| Stopped         | The service is not running.      |
| StartPending    | The service is starting.         |
| StopPending     | The service is stopping.         |
| Running         | The service is running.          |
| ContinuePending | The service continue is pending. |
| PausePending    | The service pause is pending.    |
| Paused          | The service is paused.           |

### Start Mode

The current supported start mode values:

| Value     | Description                                                                                                                      |
| --------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Boot      | Indicates that the service is a device driver started by the system loader. This value is valid only for device drivers.         |
| System    | Indicates that the service is a device driver started by the IOInitSystem function. This value is valid only for device drivers. |
| Automatic | Indicates that the service is to be started (or was started) by the operating system, at system start-up.                        |
| Manual    | Indicates that the service is started only manually, by a user (using the Service Control Manager) or by an application.         |
| Disabled  | Indicates that the service is disabled.                                                                                          |

### Type

| Value             | Description                                                                                                                                                        |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| KernelDriver      | A Kernel device driver such as a hard disk or other low-level hardware device driver.                                                                              |
| FileSystemDriver  | A file system driver, which is also a Kernel device driver.                                                                                                        |
| Adapter           | A service for a hardware device that requires its own driver.                                                                                                      |
| RecognizerDriver  | A file system driver used during startup to determine the file systems present on the system.                                                                      |
| Win32OwnProcess   | A Win32 program that can be started by the Service Controller and that obeys the service control protocol. This type of Win32 service runs in a process by itself. |
| Win32ShareProcess | A Win32 service that can share a process with other Win32 services.                                                                                                |

## Protobuf Definition

**ServiceIngestionMessage** and **ServiceIngestion** in *nemesis.proto*

## Examples

JSON:
```json
{
    "data": [
        ...
        {
            "name": "gupdate",
            "display_name": "Google Update Service (gupdate)",
            "description": "Keeps your Google software up to date. If this service is disabled or stopped, your Google software will not be kept up to date, meaning security vulnerabilities that may arise cannot be fixed and features may not work. This service uninstalls itself when there is no Google software using it.",
            "start_name": "LocalSystem",
            "state": "Stopped",
            "start_mode": "Auto",
            "type": "Win32ShareProcess",
            "service_command": "\"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe\" /svc",
            "service_sddl": "O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
        },
        ...
    ]
    "metadata": {
        "agent_id": "339429212",
        "agent_type": "beacon",
        "automated": 1,
        "data_type": "service",
        "expiration": "2023-08-01T22:51:35",
        "source": "DC",
        "project": "ASSESS-X",
        "timestamp": "2022-08-01T22:51:35"
    }
}
```