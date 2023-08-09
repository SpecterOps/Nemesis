# Standard Libraries
import asyncio
import base64
import json
import logging
import ntpath
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta

import aiohttp
import redis
import requests
from elasticsearch import Elasticsearch
# Mythic Sync Libraries
# 3rd Party Libraries
from mythic import mythic, mythic_classes
from requests.auth import HTTPBasicAuth

logging.basicConfig(format="%(levelname)s:%(message)s")
mythic_sync_log = logging.getLogger("mythic_sync_logger")
mythic_sync_log.setLevel(logging.DEBUG)

# How long to wait to make another HTTP request to see if the service has started
WAIT_TIMEOUT = 5

# the maximum file size to sync from mythic
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE"))

# the number of days past ingestion to mark the data for expiration
EXPIRATION_DAYS = int(os.environ.get("EXPIRATION_DAYS"))

# Mythic server & authentication
MYTHIC_API_KEY = os.environ.get("MYTHIC_API_KEY") or ""
MYTHIC_USERNAME = os.environ.get("MYTHIC_USERNAME") or ""
MYTHIC_PASSWORD = os.environ.get("MYTHIC_PASSWORD") or ""
MYTHIC_IP = os.environ.get("MYTHIC_IP")
if MYTHIC_IP is None:
    mythic_sync_log.error("MYTHIC_IP must be supplied!\n")
    sys.exit(1)
MYTHIC_PORT = os.environ.get("MYTHIC_PORT")
if MYTHIC_PORT is None:
    mythic_sync_log.error("MYTHIC_PORT must be supplied!\n")
    sys.exit(1)
MYTHIC_URL = f"https://{MYTHIC_IP}:{MYTHIC_PORT}"
REDIS_HOSTNAME = os.environ.get("REDIS_HOSTNAME")
if REDIS_HOSTNAME is None:
    mythic_sync_log.error("REDIS_HOSTNAME must be supplied!\n")
    sys.exit(1)
REDIS_PORT = os.environ.get("REDIS_PORT")
if REDIS_PORT is None:
    mythic_sync_log.error("REDIS_PORT must be supplied!\n")
    sys.exit(1)

# Redis connector
rconn = None

# Elasticsearch client
es_client = None

# Nemesis server/API
NEMESIS_HTTP_SERVER = os.environ.get("NEMESIS_HTTP_SERVER") or ""
NEMESIS_URL = f"{NEMESIS_HTTP_SERVER}/api"
NEMESIS_CREDS = os.environ.get("NEMESIS_CREDS") or ""
ELASTICSEARCH_URL = f"{NEMESIS_HTTP_SERVER}/elastic"
ELASTICSEARCH_USER = os.environ.get("ELASTICSEARCH_USER") or ""
ELASTICSEARCH_PASSWORD = os.environ.get("ELASTICSEARCH_PASSWORD") or ""
KIBANA_URL = f"{NEMESIS_HTTP_SERVER}/kibana"


@dataclass
class NemesisTag:
    name: str
    description: str
    color: str
    id: int = -1


NEMESIS_TAGS = {
    # File Tags
    "file_metadata": NemesisTag("file_metadata", "Metadata for the processed file.", "#16a4d8"),
    "contains_dpapi": NemesisTag("contains_dpapi", "The file contains some type of DPAPI data.", "#9b5fe0"),
    "parsed_credentials": NemesisTag("parsed_credentials", "Credentials have been parsed from a known file type.", "#60dbe8"),
    "deserialization": NemesisTag("deserialization", "The binary has a potential deserialization issue.", "#f9a52c"),
    "encrypted": NemesisTag("encrypted", "The file is encrypted.", "#8bd346"),
    "yara_matches": NemesisTag("yara_matches", "The file has known Yara matches.", "#efdf48"),
    "noseyparker": NemesisTag("noseyparker", "The file has extracted NoseyParker results.", "#d64e12"),
    "above_size_limit": NemesisTag("above_size_limit", "The file is above the processing size limit.", "#fe0000"),

    # Process Tags
    "AccessTool": NemesisTag("AccessTool", "The process name matches known access tools.", "#60dbe8"),
    "Browser": NemesisTag("Browser", "The process name matches known browsers.", "#efdf48"),
    "Infrastructure": NemesisTag("Infrastructure", "The process name matches known infrastructure tools.", "#71a0d0"),
    "MiscAwareness": NemesisTag("MiscAwareness", "The process name matches other known miscellaneous processes of iterest.", "#8bd346"),
    "Other": NemesisTag("Other", "The process name matches other known processes.", "#b390d5"),
    "Security": NemesisTag("Security", "The process name matches known security products.", "#ff1100"),
}


def nemesis_post_data(data):
    """
    Takes a json blob and POSTs it to the NEMESIS /data API endpoint.

    **Parameters**

    ``data``
        JSON formatted blob to post.

    **Returns**

    True if the request was successful, False otherwise.
    """
    try:
        basic_auth_parts = NEMESIS_CREDS.split(":")
        basic = HTTPBasicAuth(basic_auth_parts[0], basic_auth_parts[1])
        r = requests.post(f"{NEMESIS_URL}/data", auth=basic, json=data)
        if r.status_code != 200:
            mythic_sync_log.error(f"[nemesis_post_data] Error posting to Nemesis URL {NEMESIS_URL}/data ({r.status_code}) : {r.json()}")
            return None
        else:
            return r.json()
    except Exception as e:
        mythic_sync_log.error(f"[nemesis_post_data] Error : {e}")
        return None


def nemesis_post_file(file_bytes):
    """
    Takes a series of raw file bytes and POSTs it to the NEMESIS /file API endpoint.

    **Parameters**

    ``file_bytes``
        Bytes of the file we're uploading.

    **Returns**

    A new UUID string returned by the Nemesis API.
    """
    try:
        basic_auth_parts = NEMESIS_CREDS.split(":")
        basic = HTTPBasicAuth(basic_auth_parts[0], basic_auth_parts[1])
        r = requests.request("POST", f"{NEMESIS_URL}/file", auth=basic, data=file_bytes, headers={"Content-Type": "application/octet-stream"})

        if r.status_code != 200:
            mythic_sync_log.error(f"[nemesis_post_file] Error uploading file to Nemesis URL {NEMESIS_URL}: {r.status_code}")
            return None
        else:
            json_result = r.json()
            if "object_id" in json_result:
                return json_result["object_id"]
            else:
                mythic_sync_log.error("[nemesis_post_file] Error retrieving 'object_id' field from result")
                return None
    except Exception as e:
        mythic_sync_log.error(f"[nemesis_post_file] Error : {e}")
        return None


def convert_timestamp(timestamp, days_to_add=0):
    """
    Strips off the microseconds from a timestamp and reformats to our unified format.

    **Parameters**

    ``timestamp``
        The timestamp string to reformat.

    **Returns**

    A reformatted timestamp string.
    """

    dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")

    if days_to_add != 0:
        dt = dt + timedelta(days=days_to_add)

    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


async def get_processed_file_metadata(message_id: int):
    """Gets processed file metadata from Elastic search for a specific message_id."""

    query = {"bool": {"filter": [{"match_phrase": {"metadata.messageId": message_id}}]}}

    fields = [
        "path",
        "size",
        "objectId",
        "analysis",
        "magicType",
        "noseyparker",
        "nemesisFileType",
        "extractedPlaintext",
        "convertedPdf",
        "yaraMatches",
        "isBinary",
        "isOfficeDoc",
        "containsDpapi",
        "parsedData.hasParsedCredentials",
        "parsedData.isEncrypted",
        "hashes.md5",
        "metadata.messageId",
        "objectIdURL",          # link to directly download the file
        "extractedSourceURL",   # if .NET, link to download the decompiled source
        "convertedPdfURL",      # if converted to PDF, link to display that file
        "extractedPlaintextURL" # if text was extracted, link to that in elastic
    ]

    attempts = 30
    hits = {}

    while (len(hits) == 0) and (attempts > 0):
        await asyncio.sleep(3)
        try:
            resp = es_client.search(index="file_data_enriched", query=query, source=True, source_includes=fields)
            hits = resp["hits"]["hits"]
        except Exception as e:
            mythic_sync_log.debug(f"Exception: {e}, retry attempts: {attempts}")
        attempts = attempts - 1

    if len(hits) == 0:
        mythic_sync_log.error(f"No results found for message_id {message_id}")
    else:
        return hits[0]["_source"]


async def get_process_metadata(message_id: int, chunk_size: int = 100):
    """Gets process metadata from Elastic search for a specific message_id."""

    query = {"bool": {"filter": [{"match_phrase": {"metadata.messageId": message_id}}]}}

    fields = ["origin", "category"]

    attempts = 20
    hits = {}

    while (len(hits) == 0) and (attempts > 0):
        await asyncio.sleep(3)
        try:
            resp = es_client.search(index="process_category", query=query, source=True, source_includes=fields, size=chunk_size)
            hits = resp["hits"]["hits"]
        except Exception as e:
            mythic_sync_log.debug(f"Exception: {e}, retry attempts: {attempts}")
        attempts = attempts - 1

    if len(hits) == 0:
        raise Exception(f"No results found for message_id {message_id}")
    else:
        return [x["_source"] for x in hits]


async def handle_file(mythic_instance: mythic_classes.Mythic) -> None:
    """
    Start a subscription for Mythic tasks and handle them.

    **Parameters**

    ``mythic_instance``
        The Mythic instance to be used to query the Mythic database
    """

    # # clear Redis, for testing
    # for key in rconn.keys('*'):
    #     rconn.delete(key)

    try:
        start_id = rconn.get("last_file_id")
    except:
        rconn.mset({"last_file_id": 0})
        start_id = 0

    start_id = 39

    nemesis_file_subscription = """
    subscription NemesisFileSubscription {
        filemeta_stream(cursor: {initial_value: {id: %s}}, batch_size: 5, where: {is_download_from_agent: {_eq: true}, complete: {_eq: true}, is_screenshot: {_eq: false}}) {
            filename_text
            full_remote_path_text
            id
            host
            agent_file_id
            timestamp
            task {
                callback {
                    agent_callback_id
                    operation {
                        name
                    }
                }
                id
            }
            chunk_size
            chunks_received
        }
    }
    """ % (
        start_id
    )

    mythic_sync_log.info("Starting subscription for file data")
    async for data in mythic.subscribe_custom_query(mythic=mythic_instance, query=nemesis_file_subscription):
        try:
            file_meta = data["filemeta_stream"][0]
            mythic_file_id = file_meta["agent_file_id"]
            file_id = file_meta["id"]
            task_id = file_meta["task"]["id"]

            chunk_size = int(file_meta["chunk_size"])
            chunks_received = int(file_meta["chunks_received"])
            est_file_size = chunk_size * chunks_received

            redis_key = f"filemeta{mythic_file_id}"

            try:
                redis_entry_id = rconn.get(redis_key)
            except:
                redis_entry_id = None

            if not redis_entry_id:

                mythic_sync_log.info(f"New file download with id '{mythic_file_id}'")

                # TODO: depending on file size, determine if we want to hold this in memory
                #   Is there some other option that lets us stream to disk instead?

                if est_file_size > MAX_FILE_SIZE:
                    await add_mythic_tag(mythic_instance, "above_size_limit", filemeta_id=file_id, task_id=task_id)
                    raise Exception(f"File is over {MAX_FILE_SIZE} bytes, not processing")

                # download the file bytes from Mythic
                #   TODO: chunking to get around the size limit?
                file_bytes = await mythic.download_file(mythic=mythic_instance, file_uuid=mythic_file_id)
                file_size = len(file_bytes)

                # upload the file to Nemesis and get a new file UUID back for reference
                nemesis_file_id = nemesis_post_file(file_bytes)
                mythic_sync_log.info(f"File posted to Nemesis, nemesis_file_id: {nemesis_file_id}")

                if not nemesis_file_id:
                    raise Exception("No nemesis_file_id returned from file upload")

                del file_bytes

                metadata = {}
                metadata["agent_id"] = file_meta["task"]["callback"]["agent_callback_id"]
                metadata["agent_type"] = "mythic"
                metadata["automated"] = True
                metadata["data_type"] = "file_data"
                metadata["expiration"] = convert_timestamp(file_meta["timestamp"], EXPIRATION_DAYS)
                # metadata["source"] = file_meta["host"]
                metadata["project"] = file_meta["task"]["callback"]["operation"]["name"]
                metadata["timestamp"] = convert_timestamp(file_meta["timestamp"])

                file_data = {}
                file_data["path"] = base64.b64decode(file_meta["full_remote_path_text"]).decode("utf-8").replace("\\", "/")
                # filename_text = base64.b64decode(file_meta["filename_text"]).decode("utf-8")
                file_data["size"] = file_size
                file_data["object_id"] = nemesis_file_id

                # post to the Nemesis data API (`data`` needs to be an array of dictionaries!)
                resp = nemesis_post_data({"metadata": metadata, "data": [file_data]})

                message_id = resp["object_id"]
                mythic_sync_log.info(f"Nemesis message_id for submitted file_data: {message_id}")

                # mark this file as processed in Redis now that it was submitted
                rconn.mset({redis_key: 1})

                # mark this Mythic ID as the last processed file ID
                last_file_id = rconn.get("last_file_id")
                if file_id > last_file_id:
                    rconn.mset({"last_file_id": file_id})

                # get the metadata for the processed file from Elasticsearch
                file_metadata = await get_processed_file_metadata(message_id)

                if not file_metadata:
                    mythic_sync_log.error("Couldn't retrieve metadata for processed file!")
                    continue

                mythic_sync_log.debug(f"File metadata for {message_id} retrieved from Elastic")

                # this is any metadata that we're doing to display as JSON for the "file_metadata" tag
                file_metadata_display = {}
                if "size" in file_metadata and file_metadata["size"]:
                    file_metadata_display["size"] = file_metadata["size"]
                if "isBinary" in file_metadata and file_metadata["isBinary"]:
                    file_metadata_display["is_binary"] = "true"
                if "isOfficeDoc" in file_metadata and file_metadata["isOfficeDoc"]:
                    file_metadata_display["is_office_doc"] = "true"
                if "magicType" in file_metadata and file_metadata["magicType"]:
                    file_metadata_display["magic_type"] = file_metadata["magicType"]
                if "nemesisFileType" in file_metadata and file_metadata["nemesisFileType"]:
                    file_metadata_display["nemesis_file_type"] = file_metadata["nemesisFileType"]

                if "objectIdURL" in file_metadata and file_metadata["objectIdURL"]:
                    file_metadata_display["Download File"] = file_metadata["objectIdURL"]
                if "extractedSourceURL" in file_metadata and file_metadata["extractedSourceURL"]:
                    file_metadata_display["Download Decompiled Source"] = file_metadata["extractedSourceURL"]
                if "convertedPdfURL" in file_metadata and file_metadata["convertedPdfURL"]:
                    file_metadata_display["View Converted PDF"] = file_metadata["convertedPdfURL"]
                if "extractedPlaintextURL" in file_metadata and file_metadata["extractedPlaintextURL"]:
                    file_metadata_display["Extracted Plaintext (Elastic)"] = file_metadata["extractedPlaintextURL"]

                # TODO: fixate the index ID
                kibana_file_link = f"{KIBANA_URL}/app/discover#/?_a=(filters:!((query:(match_phrase:(objectId:'{nemesis_file_id}')))))&_g=(time:(from:now-1y%2Fd,to:now))"

                # update the comment for the file in Mythic to indicate it was processed
                await mythic.update_file_comment(mythic_instance, file_uuid=mythic_file_id, comment="Processed by Nemesis 😈")

                # add a basic metadata Mythic tag
                await add_mythic_tag(mythic_instance, "file_metadata", filemeta_id=file_id, task_id=task_id, url=kibana_file_link, data=json.dumps(file_metadata_display))

                # custom tags
                if ("containsDpapi" in file_metadata) and (file_metadata["containsDpapi"]):
                    await add_mythic_tag(mythic_instance, "contains_dpapi", filemeta_id=file_id, task_id=task_id, url=kibana_file_link)

                if ("parsedData" in file_metadata) and ("hasParsedCredentials" in file_metadata["parsedData"]) and file_metadata["parsedData"]["hasParsedCredentials"]:
                    await add_mythic_tag(mythic_instance, "parsed_credentials", filemeta_id=file_id, task_id=task_id, url=kibana_file_link)

                if ("analysis" in file_metadata) and ("dotnetDeserialization" in file_metadata["analysis"]) and (file_metadata["analysis"]["dotnetDeserialization"]["hasDeserialization"] == 1):
                    await add_mythic_tag(mythic_instance, "deserialization", filemeta_id=file_id, task_id=task_id, url=kibana_file_link)

                if ("parsedData" in file_metadata) and ("isEncrypted" in file_metadata["parsedData"]) and file_metadata["parsedData"]["isEncrypted"]:
                    await add_mythic_tag(mythic_instance, "encrypted", filemeta_id=file_id, task_id=task_id, url=kibana_file_link)

                if ("yaraMatches" in file_metadata) and (file_metadata["yaraMatches"]):
                    rule_names = ", ".join(file_metadata["yaraMatches"])
                    data = json.dumps({"rule_names": rule_names})
                    await add_mythic_tag(mythic_instance, "yara_matches", filemeta_id=file_id, task_id=task_id, url=kibana_file_link, data=data)

                if ("noseyparker" in file_metadata) and (file_metadata["noseyparker"]):
                    rule_names_dict = {}
                    for match in file_metadata["noseyparker"]["ruleMatches"]:
                        rule_names_dict[match["ruleName"]] = True
                    rule_names = ", ".join(rule_names_dict.keys())
                    data = json.dumps({"rule_names": rule_names})
                    await add_mythic_tag(mythic_instance, "noseyparker", filemeta_id=file_id, task_id=task_id, url=kibana_file_link, data=data)

        except Exception:
            mythic_sync_log.exception(
                "Encountered an exception! Data returned by Mythic: %s",
                data,
            )
            continue


async def handle_filebrowser(mythic_instance: mythic_classes.Mythic) -> None:
    """
    Start a subscription for Mythic tasks and handle them.

    **Parameters**

    ``mythic_instance``
        The Mythic instance to be used to query the Mythic database
    """

    try:
        start_id = rconn.get("last_filebrowser_id")
    except:
        rconn.mset({"last_filebrowser_id": 0})
        start_id = 0

    nemesis_filebrowser_subscription = """
    subscription NemesisFileBrowserSubscription {
        mythictree_stream(batch_size: 100, cursor: {initial_value: {id: %s}}, where: {tree_type: {_eq: "file"}}) {
            id
            host
            full_path_text
            name_text
            parent_path_text
            timestamp
            can_have_children
            metadata
        }
    }
    """ % (
        start_id
    )

    mythic_sync_log.info("Starting subscription for file browser information")
    async for data in mythic.subscribe_custom_query(mythic=mythic_instance, query=nemesis_filebrowser_subscription):

        # group by the agent ID
        all_data = {}

        files = data["mythictree_stream"]

        for file in files:
            mythic_id = file["id"]
            redis_key = f"filebrowser{mythic_id}"

            try:
                redis_entry_id = rconn.get(redis_key)
            except:
                redis_entry_id = None

            if not redis_entry_id:
                callback_id = file["task"]["callback"]["agent_callback_id"]

                # build the metadata entry on first encounter of this agent ID
                if callback_id not in all_data:
                    metadata = {}
                    metadata["agent_id"] = callback_id
                    metadata["agent_type"] = "mythic"
                    metadata["automated"] = True
                    metadata["data_type"] = "process"
                    metadata["expiration"] = convert_timestamp(file["timestamp"], EXPIRATION_DAYS)
                    metadata["source"] = file["host"]
                    metadata["project"] = file["task"]["callback"]["operation"]["name"]
                    metadata["timestamp"] = convert_timestamp(file["timestamp"])

                    all_data[callback_id] = {}
                    all_data[callback_id]["metadata"] = metadata
                    all_data[callback_id]["data"] = list()

                file_data = {}
                file_data["path"] = file["full_path_text"].replace("\\", "/")
                file_data["size"] = file["metadata"]["size"]

                if file["can_have_children"]:
                    file_data["type"] = "folder"
                else:
                    file_data["type"] = "file"

                if "access_time" in file["metadata"] and file["metadata"]["access_time"]:
                    file_data["access_time"] = convert_timestamp(file["metadata"]["access_time"])
                if "modify_time" in file["metadata"] and file["metadata"]["modify_time"]:
                    file_data["modification_time"] = convert_timestamp(file["metadata"]["modify_time"])

                # TODO: translate file["metadata"]["permissions"] to sddl

                all_data[callback_id]["data"].append(file_data)

                # mark this file browser entry as seen
                # TODO: does this need to be after the nemesis_post_data call?
                rconn.mset({redis_key: 1})

                # mark this Mythic ID as the last processed process ID
                last_filebrowser_id = rconn.get("last_filebrowser_id")
                if mythic_id > last_filebrowser_id:
                    rconn.mset({"last_filebrowser_id": mythic_id})

        # for each unique agent ID, issue one request with all batched file browser information
        #   but using the same metadata entry
        for key in all_data:
            nemesis_post_data(all_data[key])


async def handle_process(mythic_instance: mythic_classes.Mythic, chunk_size: int = 100) -> None:
    """
    **Parameters**

    ``mythic_instance``
        The Mythic instance to be used to query the Mythic database

    ``chunk_size``
        The number of process results to handle at a time.
    """

    # # clear Redis, for testing
    # for key in rconn.keys("*"):
    #     rconn.delete(key)

    try:
        start_id = rconn.get("last_process_id")
    except:
        rconn.mset({"last_process_id": 0})
        start_id = 0

    nemesis_process_subscription = """
    subscription NemesisProcessSubscription {
        mythictree_stream(batch_size: %s, cursor: {initial_value: {id: %s}}, where: {tree_type: {_eq: "process"}}) {
            id
            metadata
            host
            timestamp
            task {
                callback {
                    agent_callback_id
                    operation {
                        name
                    }
                }
            }
        }
    }
    """ % (chunk_size, start_id)

    mythic_sync_log.info("Starting subscription for process data")
    async for data in mythic.subscribe_custom_query(mythic=mythic_instance, query=nemesis_process_subscription):

        # group by the callback ID
        all_data = {}

        # lookup table to get the process entry ID easily, keyed by callback ID
        mythic_process_lookup_table = {}

        processes = data["mythictree_stream"]

        for process in processes:
            mythic_id = process["id"]
            redis_key = f"process{mythic_id}"

            try:
                redis_entry_id = rconn.get(redis_key)
            except:
                redis_entry_id = None

            if not redis_entry_id:
                callback_id = process["task"]["callback"]["agent_callback_id"]

                # build the metadata entry on first encounter of this agent ID
                if callback_id not in all_data:
                    metadata = {}
                    metadata["agent_id"] = callback_id
                    metadata["agent_type"] = "mythic"
                    metadata["automated"] = True
                    metadata["data_type"] = "process"
                    metadata["expiration"] = convert_timestamp(process["timestamp"], EXPIRATION_DAYS)
                    metadata["source"] = process["host"]
                    metadata["project"] = process["task"]["callback"]["operation"]["name"]
                    metadata["timestamp"] = convert_timestamp(process["timestamp"])

                    all_data[callback_id] = {}
                    all_data[callback_id]["metadata"] = metadata
                    all_data[callback_id]["data"] = list()

                # integrity levels:
                #   0 - unknown
                #   1 - low
                #   2 - medium
                #   3 - high
                #   4 - system
                process_data = {}
                process_data["name"] = process["metadata"]["name"]
                process_data["command_line"] = process["metadata"]["command_line"]

                if ("bin_path" in process["metadata"]) and (process["metadata"]["bin_path"]):
                    process_data["file_name"] = ntpath.basename(process["metadata"]["bin_path"])
                    if process_data["file_name"]:
                        process_data["name"] = process_data["file_name"]

                process_data["process_id"] = process["metadata"]["process_id"]
                process_data["parent_process_id"] = process["metadata"]["parent_process_id"]
                process_data["arch"] = process["metadata"]["architecture"]

                # if ("start_time" in process["metadata"]) and (process["metadata"]["start_time"] is not None) and (process["metadata"]["start_time"] != 0):
                #     process_data["start_time"] = convert_timestamp(process["metadata"]["start_time"])

                process_data["token"] = {"user": {"name": process["metadata"]["user"]}}

                all_data[callback_id]["data"].append(process_data)

                if callback_id not in mythic_process_lookup_table:
                    mythic_process_lookup_table[callback_id] = {}

                # map {name}{process_id} to the mythictree ID for later tagging
                name = process_data["name"]
                process_id = process_data["process_id"]
                key = f"{name}{process_id}"
                mythic_process_lookup_table[callback_id][key] = mythic_id

                # mark this process entry as seen
                # TODO: does this need to be after the nemesis_post_data call?
                rconn.mset({redis_key: 1})

                # mark this Mythic ID as the last processed process ID
                last_process_id = rconn.get("last_process_id")
                if mythic_id > last_process_id:
                    rconn.mset({"last_process_id": mythic_id})

        # for each unique agent ID, issue one request with all batched processes
        #   but using the same metadata entry
        for key in all_data:
            resp = nemesis_post_data(all_data[key])
            message_id = resp["object_id"]
            mythic_sync_log.info(f"Nemesis message_id for submitted process data: {message_id}")

            # get the metadata for the processed file from Elasticsearch
            nemesis_processes = await get_process_metadata(message_id, chunk_size)

            for nemesis_process in nemesis_processes:
                if "name" in nemesis_process["origin"]:
                    name = nemesis_process["origin"]["name"]
                else:
                    name = ""

                if "processId" in nemesis_process["origin"]:
                    process_id = nemesis_process["origin"]["processId"]
                else:
                    process_id = ""

                tag_calls = []
                key = f"{name}{process_id}"
                if key in mythic_process_lookup_table[callback_id]:
                    category = nemesis_process["category"]["category"]

                    if category != "Unknown":
                        mythictree_id = mythic_process_lookup_table[callback_id][key]

                        if "description" in nemesis_process["category"]:
                            description = nemesis_process["category"]["description"]
                            data = json.dumps({"description": description})
                        else:
                            data = ""

                        tag_calls.append(add_mythic_tag(mythic_instance, category, mythictree_id=mythictree_id, data=data))

                await asyncio.gather(*tag_calls)


async def add_mythic_tag(mythic_instance: mythic_classes.Mythic, tag_name: str, source: str = "Nemesis", filemeta_id: int = -1, mythictree_id: int = -1, task_id: int = -1, url: str = "", data: str = ""):
    """Adds a file or process tag from an existing tag type."""

    if filemeta_id != -1:
        filemeta_ids = [filemeta_id]
    else:
        filemeta_ids = None

    if mythictree_id != -1:
        mythictree_ids = [mythictree_id]
    else:
        mythictree_ids = None

    if task_id != -1:
        task_ids = [task_id]
    else:
        task_ids = None

    if tag_name not in NEMESIS_TAGS:
        mythic_sync_log.warning(f"Tag name '{tag_name}' not in the existing tag set.")
    else:
        if NEMESIS_TAGS[tag_name].id == -1:
            mythic_sync_log.warning(f"Tag name '{tag_name}' not initialized properly.")
        else:
            await mythic.create_tag(mythic=mythic_instance, tag_type_id=NEMESIS_TAGS[tag_name].id, filemeta_ids=filemeta_ids, mythictree_ids=mythictree_ids, task_ids=task_ids, source=source, url=url, data=data)


async def create_tag_types(mythic_instance: mythic_classes.Mythic):
    """Creates the Mythic tag types from NEMESIS_TAGS."""

    for tag_name, tag in NEMESIS_TAGS.items():
        tag_info = await mythic.create_tag_type(mythic=mythic_instance, color=tag.color, description=tag.description, name=tag_name)
        # save this ID off for caching
        if "id" in tag_info:
            tag.id = tag_info["id"]


async def wait_for_service() -> None:
    """Wait for an HTTP session to be established with Mythic."""
    while True:
        mythic_sync_log.info(f"Attempting to connect to {MYTHIC_URL}")
        async with aiohttp.ClientSession() as session:
            async with session.get(MYTHIC_URL, ssl=False) as resp:
                if resp.status != 200:
                    mythic_sync_log.warning(
                        "Expected 200 OK and received HTTP code %s while trying to connect to Mythic, trying again in %s seconds...",
                        resp.status,
                        WAIT_TIMEOUT,
                    )
                    await asyncio.sleep(WAIT_TIMEOUT)
                    continue
        return


async def wait_for_redis() -> None:
    """Wait for a connection to be established with Mythic's Redis container."""
    global rconn
    while True:
        try:
            rconn = redis.Redis(host=REDIS_HOSTNAME, port=REDIS_PORT, db=1)
            # we're only using ints for our redis DB
            rconn.set_response_callback("GET", int)
            return
        except Exception:
            mythic_sync_log.exception(
                "Encountered an exception while trying to connect to Redis, %s:%s, trying again in %s seconds...",
                REDIS_HOSTNAME,
                REDIS_PORT,
                WAIT_TIMEOUT,
            )
            await asyncio.sleep(WAIT_TIMEOUT)
            continue


async def wait_for_authentication() -> mythic_classes.Mythic:
    """Wait for authentication with Mythic to complete."""
    while True:
        # If ``MYTHIC_API_KEY`` is not set in the environment, then authenticate with user credentials
        if len(MYTHIC_API_KEY) == 0:
            mythic_sync_log.info(
                "Authenticating to Mythic, https://%s:%s, with username and password",
                MYTHIC_IP,
                MYTHIC_PORT,
            )
            try:
                mythic_instance = await mythic.login(
                    username=MYTHIC_USERNAME,
                    password=MYTHIC_PASSWORD,
                    server_ip=MYTHIC_IP,
                    server_port=MYTHIC_PORT,
                    ssl=True,
                    timeout=-1,
                )
            except Exception:
                mythic_sync_log.exception(
                    "Encountered an exception while trying to authenticate to Mythic, trying again in %s seconds...",
                    WAIT_TIMEOUT,
                )
                await asyncio.sleep(WAIT_TIMEOUT)
                continue
            try:
                # await mythic.get_me(mythic=mythic_instance) # TODO: replace?
                pass
            except Exception:
                mythic_sync_log.exception(
                    "Encountered an exception while trying to authenticate to Mythic, trying again in %s seconds...",
                    WAIT_TIMEOUT,
                )
                await asyncio.sleep(WAIT_TIMEOUT)
                continue
        elif MYTHIC_USERNAME == "" and MYTHIC_PASSWORD == "":
            mythic_sync_log.error("You must supply a MYTHIC_USERNAME and MYTHIC_PASSWORD")
            sys.exit(1)
        elif NEMESIS_URL == "":
            mythic_sync_log.error("You must supply a NEMESIS_URL")
            sys.exit(1)
        elif NEMESIS_CREDS == "":
            mythic_sync_log.error("You must supply NEMESIS_CREDS")
            sys.exit(1)
        else:
            mythic_sync_log.info(
                "Authenticating to Mythic, https://%s:%s, with a specified API Key",
                MYTHIC_IP,
                MYTHIC_PORT,
            )
            try:
                mythic_instance = await mythic.login(
                    apitoken=MYTHIC_API_KEY,
                    server_ip=MYTHIC_IP,
                    server_port=MYTHIC_PORT,
                    ssl=True,
                    global_timeout=-1,
                )
                # await mythic.get_me(mythic=mythic_instance) # TODO: replace?
            except Exception:
                mythic_sync_log.exception(
                    "Failed to authenticate with the Mythic API token, trying again in %s seconds...",
                    WAIT_TIMEOUT,
                )
                await asyncio.sleep(WAIT_TIMEOUT)
                continue

        return mythic_instance


async def wait_for_elasticsearch() -> None:
    """Wait for a connection to be established with Nemesis' Elasticsearch container."""
    global es_client
    while True:
        try:
            es_client = Elasticsearch(ELASTICSEARCH_URL, basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD), verify_certs=False)
            es_client.info()
            return
        except Exception:
            mythic_sync_log.exception(
                "Encountered an exception while trying to connect to Elasticsearch %s, trying again in %s seconds...",
                ELASTICSEARCH_URL,
                WAIT_TIMEOUT,
            )
            await asyncio.sleep(WAIT_TIMEOUT)
            continue


async def scripting():
    while True:
        await wait_for_redis()
        mythic_sync_log.info("Successfully connected to Redis")
        await wait_for_elasticsearch()
        mythic_sync_log.info("Successfully connected to Nemesis-Elasticsearch")
        await wait_for_service()
        mythic_sync_log.info(f"Successfully connected to {MYTHIC_URL}")
        mythic_sync_log.info("Trying to authenticate to Mythic")
        mythic_instance = await wait_for_authentication()
        mythic_sync_log.info("Successfully authenticated to Mythic")
        # create our initial tags
        mythic_sync_log.info("Creating tag types")
        await create_tag_types(mythic_instance)
        mythic_sync_log.info("Successfully created tag types")

        try:
            _ = await asyncio.gather(
                handle_file(mythic_instance=mythic_instance),
                # handle_process(mythic_instance=mythic_instance),
                # handle_filebrowser(mythic_instance=mythic_instance),
            )
        except Exception:
            mythic_sync_log.exception("Encountered an exception while subscribing to tasks and responses, restarting...")


asyncio.run(scripting())
