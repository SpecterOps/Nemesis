# Network Connections
Date type: `network_connection`

## Overview

Connections between the host the agent is running with itself or another host. These could also be listening ports (i.e., netstat output).Addresses are expected to conform to the public standard for the address type but there is no verification of this as well. As an example, ethernet addresses are expected to use a hyphen as a separator instead of a colon as per IEEE 802.3 but this is not verified.

The protocol list and matching source and destination lists represent the protocol stack used for a connection. The lists only need to represent a portion of the protocol stack and do not need to represent the entirety of it. The lists allow the ODR to be reused for any connection type an operator may be interested in without having to make a new ODR for each new connectiontype.

local_address is treated as source, remote_address is treated as destination.

| Parameters     | Format | Description                                                                           |
| -------------- | ------ | ------------------------------------------------------------------------------------- |
| local_address  | string | Local/source address for the connection.                                              |
| remote_address | string | Remote/destination address for the connection.                                        |
| protocol       | string | Protocol specification ("tcp,ipv4", "udp,ipv4", "tcp,ipv6", etc.)                     |
| state          | string | Optional - case insensitive state of the connection (e.g., listen, established, etc.) |
| process_id     | int    | Optional - process ID handling the connection                                         |
| process_name   | string | Optional - process name handling the connection                                       |
| service        | string | Optional - service name handling the connection                                       |

### State

The current supported state values (same as `netstat`):

| State       | Description                                                                  |
| ----------- | ---------------------------------------------------------------------------- |
| ESTABLISHED | A connection has been established.                                           |
| SYN_SENT    | The local_address is attempting to establish a connection.                   |
| SYN_RECV    | The local_address has received a connection request.                         |
| FIN_WAIT1   | The connection is shutting down.                                             |
| FIN_WAIT2   | The local_address is waiting for a shutdown from the remote end.             |
| TIME_WAIT   | local_address is waiting after close to handle packets still in the network. |
| CLOSED      | The socket is closed.                                                        |
| CLOSE_WAIT  | remote_address has shut down.                                                |
| LAST_ACK    | remote_address has shut down, waiting for acknowledgement.                   |
| LISTEN      | local_address is for incoming connections.                                   |
| CLOSING     | Both sides have shut down but not all data has been sent.                    |
| UNKNOWN     | Unknown state.                                                               |


## Protobuf Definition

**NetworkConnectionIngestionMessage** and **NetworkConnectionIngestion** in *nemesis.proto*

## Examples
```json
{
    "data": [
        ...
        {
            "local_address": "172.16.111.218:52279",
            "remote_address": "172.16.111.171:80",
            "protocol": "tcp,ipv4",
            "state": "ESTABLISHED",
            "process_id": 1260,
            "process_name": "program.exe"
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