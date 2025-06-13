# Nosey Parker Scanner with Dapr and MinIO Integration

A microservice that uses the Nosey Parker library to scan files for secrets, with Dapr pub/sub messaging and MinIO integration for file storage.

Nosey Parker's source is located at [https://github.com/praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker) and is maintained by [Praetorian](https://praetorian.com/) under the Apache License, Version 2.0

## Overview

This service integrates Nosey Parker for secret scanning with:
- **Dapr** for pub/sub messaging
- **MinIO** for object storage

The workflow is:

1. Service listens for events on a pub/sub topic
2. When a message arrives, it downloads the specified file from MinIO
3. The file is scanned for secrets using Nosey Parker
4. Results are published to an output topic

## ENV variables

The following ENV variables can be set:

| Variable         | Default            | Description                                         |
| ---------------- | ------------------ | --------------------------------------------------- |
| DAPR_PORT        | 3500               | The HTTP DAPR port (not currently used)             |
| DAPR_GRPC_PORT   | 50001              | The GRPC DAPR port                                  |
| PUBSUB_NAME      | pubsub             | The name of the Dapr pub/sub queue to use           |
| INPUT_TOPIC      | noseyparker-input  | The name of the pub/sub input topic to subscribe to |
| OUTPUT_TOPIC     | noseyparker-output | The name of the pub/sub output topic to publish to  |
| SNIPPET_LENGTH   | 512                | Length of surrounding context to pull on a match    |
| MINIO_ENDPOINT   | none               | Minio server to download files from                 |
| MINIO_BUCKET     | none               | Bucket name to download files from                  |
| MINIO_ACCESS_KEY | none               | Minio access key                                    |
| MINIO_SECRET_KEY | none               | Minio secret key                                    |


## Message Format

### Input Messages

```json
{
  "object_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Output Messages

```json
{
  "object_id": "550e8400-e29b-41d4-a716-446655440000",
  "scan_result": {
    "scan_duration_ms": 15,
    "bytes_scanned": 2020,
    "matches": [
      {
        "rule_name": "AWS API Key",
        "rule_type": "secret",
        "matched_content": "AKIAIOSFODNN7EXAMPLE",
        "location": {
          "line": 3,
          "column": 17
        },
        "snippet": "...context around the match..."
      }
    ],
    "stats": {
      "blobs_seen": 1,
      "blobs_scanned": 1,
      "bytes_seen": 2020,
      "bytes_scanned": 2020,
      "matches_found": 5
    }
  }
}
```
