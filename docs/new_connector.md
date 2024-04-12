# Creating a New Connector

There are several levels of integrating a C2's output into Nemesis. The easiest start and the best bang for the buck is the processing of file downloads.

Regardless of the connector actions, it will need to somehow save the following configuration values:

| Description                               | Example                      |
| ----------------------------------------- | ---------------------------- |
| Address of the Nemesis endpoint           | https://<NEMESIS_URL>/api     |
| Nemesis basic-auth connection credentials | nemesis:Qwerty12345          |
| Project name                              | PROJECT-X                    |
| Expiration days (or date)                 | 100 (or 01/01/2024)          |

# Download Processing

File processing is the one flow that differs from other structured data ingestion. First, the file bytes need to be uploaded to Nemesis, and second, a metadata message needs to be posted to kick off processing.

## Step 1 - File Upload

For a file to be processed, the raw file bytes first need to be posted to the correct API route for storage in the data lake. This is accomplished by POSTing the file bytes to the `https://<NEMESIS_URL>/api/file` which returns a simple JSON response with an `object_id` field containing a UUID that references the uploaded file. For example, to do this in Python (as shown in [mythic-connector](https://github.com/SpecterOps/Nemesis/blob/main/cmd/connectors/mythic-connector/sync.py)), you would run something like this:

```python
basic = HTTPBasicAuth(NEMESIS_USERNAME, NEMESIS_PASSWORD)
r = requests.request("POST", f"{NEMESIS_URL}/file", auth=basic, data=file_bytes, headers={"Content-Type": "application/octet-stream"})
json_result = r.json()
nemesis_file_id = json_result["object_id"]
```
The equivalent `curl` command:
```bash
curl -H "Content-Type: application/octet-stream" -v --user 'nemesis:Qwerty12345' -k --data-binary @/etc/issue https://192.168.230.42:8080/api/file
```

The `nemesis_file_id` is used in the `file_data` message in Step 2 below. This UUID is the unique reference for the file in Nemesis.

## Step 2 - File Data Message

After the file is uploaded to Nemesis, a [file_data](odr/references/file_data.md) ODR message needs to be posted with file metadata information. The example from the [mythic-connector](https://github.com/SpecterOps/Nemesis/blob/main/cmd/connectors/mythic-connector/sync.py) is:

```python
metadata = {}
metadata["agent_id"] = file_meta["task"]["callback"]["agent_callback_id"]
metadata["agent_type"] = "mythic"
metadata["automated"] = True
metadata["data_type"] = "file_data"
# add EXPIRATION_DAYS to the timestamp
metadata["expiration"] = convert_timestamp(file_meta["timestamp"], EXPIRATION_DAYS)
metadata["project"] = file_meta["task"]["callback"]["operation"]["name"]
metadata["timestamp"] = convert_timestamp(file_meta["timestamp"])

file_data = {}
file_data["path"] = base64.b64decode(file_meta["full_remote_path_text"]).decode("utf-8").replace("\\", "/")
file_data["size"] = file_size
file_data["object_id"] = nemesis_file_id

# post to the Nemesis data API (`data`` needs to be an array of dictionaries!)
data = {"metadata": metadata, "data": [file_data]}

basic = HTTPBasicAuth(NEMESIS_USERNAME, NEMESIS_PASSWORD)
r = requests.request("POST", f"{NEMESIS_URL}/data", auth=basic, data=data, headers={"Content-Type": "application/octet-stream"})
```

*Note that timestamps need to be in ISO 8601 UTC form, e.g., 2023-08-01T22:51:35*


# Other Structured Data

For other types of structured data, only a single message needs to be posted to the `http://<NEMESIS_URL>/api/data` API route, e.g. Step 2 in the downloading processing example. The `metadata["data_type"]` field should be one of the types defined in the [ODR](odr/references/). The appropriate ODR document will also define the fields and structure needed for the datatype.

Note that the "data" section of the message is an array of dictionaries, i.e., multiple instances of a datatype can be posted in a single message. For example, multiple process messages can exist in the single post.

As an example, see the `handle_process()` function in the [mythic-connector](https://github.com/SpecterOps/Nemesis/blob/main/cmd/connectors/mythic-connector/sync.py).

Example of many of the structured datatypes can be found in the `./sample_files/structured/` folder. Example of using these to submit process data:
```bash
curl -H "Content-Type: application/octet-stream" -k -v --user 'nemesis:Qwerty12345' --data-binary @./sample_files/structured/process_data.json https://192.168.230.42:8080/api/data
```
