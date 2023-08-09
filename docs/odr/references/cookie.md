# Registry Value
Date type: `cookie`

## Overview
...

### Message format:

| Parameters          | Format    | Description                                                       |
| ------------------- | --------- | ----------------------------------------------------------------- |
| user_data_directory | string    | Path of the user data folder, if known.                           |
| domain              | string    | Domain/host key for the cookie.                                   |
| path                | string    | Path on the domain for the cookie.                                |
| name                | string    | Name of the cookie value.                                         |
| value               | string    | Plaintext decrypted cookie value (if decrypted).                  |
| value_enc           | string    | Base64 encoding of encrypted value bytes.                         |
| expires             | timestamp | Timestamp of when the cookie expires.                             |
| creation            | timestamp | Timestamp of when the cookie was created.                         |
| last_access         | timestamp | Timestamp of when the cookie was last accessed.                   |
| last_update         | timestamp | Timestamp of when the cookie was last updated.                    |
| secure              | bool      | True if the cookie can only be sent over HTTPS.                   |
| http_only           | bool      | True if the cookie can only be accessed by the server.            |
| session             | bool      | True if the cookie is deleted when the user closes their browser. |
| samesite            | string    | strict/lax/none, protection against CSRF attacks.                 |
| source_port         | int       | The port number of the source origin.                             |

## Protobuf Definition

**CookieIngestionMessage** and **CookieIngestion** in *nemesis.proto*

## Examples
```json
{
    "data": [
        ...
        {
            "user_data_directory": "C:/Users/harmj0y/AppData/Local/Google/Chrome/User Data/Default/Cookies",
            "domain": "example.com",
            "path": "/",
            "name": "username",
            "value": "harmj0y",
            "expires": "2024-01-01T01:01:01.000Z",
            "creation": "2023-01-01T01:01:01.000Z",
            "last_access": "2023-01-01T01:01:01.000Z",
            "last_update": "2023-01-01T01:01:01.000Z",
            "secure": true,
            "http_only": false,
            "session": false,
            "samesite": "LAX",
            "source_port": 8443
        }
        ...
    ],
    "metadata": {
        "agent_id": "339429212",
        "agent_type": "beacon",
        "automated": false,
        "data_type": "cookie",
        "expiration": "2024-04-03T10:08:40.000Z",
        "source": "DC",
        "project": "ASSESS-X",
        "timestamp": "2023-04-03T10:08:40.000Z"
    }
}
```

