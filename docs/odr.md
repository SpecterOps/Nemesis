# Operational Data Reference

This Operational Data Reference (ODR) is the key a reference for how data should be formated to be accepted and parsed by the Nemesis. The Nemesis 2.0 ODR is significantly simpler than the Nemesis 1.X ODR and consists solely of a [file](#file) entry.

## File
Schema definition for the public `file` message POSTed to the API frontend.

## Message Structure

### Required Fields

| Field        | Type     | Description                                                                    |
| ------------ | -------- | ------------------------------------------------------------------------------ |
| `object_id`  | string   | UUID v4 format identifier for the current object                               |
| `agent_id`   | string   | Identifier for the processing agent                                            |
| `project`    | string   | Project identifier                                                             |
| `timestamp`  | datetime | ISO 8601 formatted timestamp indicating when the file was downloaded           |
| `expiration` | string   | ISO 8601 formatted timestamp indicating when the data should expire in Nemesis |

### Optional Fields

| Field                   | Type     | Description                                                                                                      |
| ----------------------- | -------- | ---------------------------------------------------------------------------------------------------------------- |
| `path`                  | string   | File system path to the relevant resource. Can use either forward (/) or backward (\\) slashes                   |
| `originating_object_id` | string   | UUID v4 format identifier referencing a parent or source object                                                  |
| `nesting_level`         | number   | The level of nesting for the file within an originating container. Used to prevent indefinite container nesting. |
| `creation_time`         | datetime | ISO 8601 formatted timestamp for when the file was created                                                       |
| `access_time`           | datetime | ISO 8601 formatted timestamp for when the file was last accessed                                                 |
| `modification_time`     | datetime | ISO 8601 formatted timestamp for when the file was last modified                                                 |


## Example Message - Derivative File
```json
{
  "agent_id": "339429212",
  "project": "assess-X",
  "timestamp": "2024-08-01T22:51:35",
  "expiration": "2025-08-01T22:51:35",
  "path": "C:\\temp\\file.txt",
  "object_id": "2f0a4f7a-6b97-4869-a8b6-d7df3c9f5124",
  "originating_object_id": "f309b012-d0a1-4639-bd29-77a4dc582576"
}
```

## Example Message - File Extracted from a Container
```json
{
  "agent_id": "339429212",
  "project": "assess-X",
  "timestamp": "2024-08-01T22:51:35",
  "expiration": "2025-08-01T22:51:35",
  "path": "C:\\temp\\file.txt",
  "object_id": "2f0a4f7a-6b97-4869-a8b6-d7df3c9f5124",
  "originating_object_id": "f309b012-d0a1-4639-bd29-77a4dc582576",
  "nesting_level": 1
}
```

## Notes
- All timestamps must be in ISO 8601 format with timezone information
- File paths can use either forward (/) or backward (\\) slashes
- UUIDs should follow the v4 format
- The schema may be extended with additional optional fields in the future
- If `originating_object_id` is present but `nesting_level` is not or is 0, then the file is a derivative file.
- If `originating_object_id` is present and `nesting_level` is present and > 0, then the file was extracted from a container.