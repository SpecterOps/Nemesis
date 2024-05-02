#!/usr/bin/python3

# Standard Libraries
import argparse
import asyncio
import functools
import glob
import json
import os
import random
import re
import sys
import uuid
from datetime import datetime, timedelta
from typing import Any, AsyncIterator, Callable, Dict, Iterator, List, Optional, Tuple

# 3rd Party Libraries
import httpx
import requests
import structlog
import urllib3
import yaml
from enrichment.cli.submit_to_nemesis.file_monitoring import monitor_directory
from nemesiscommon.apiclient import FileUploadRequest, NemesisApiClient
from nemesiscommon.logging import configure_logger
from nemesiscommon.settings import EnvironmentSettings
from structlog.typing import FilteringBoundLogger

urllib3.disable_warnings()

logger: FilteringBoundLogger


async def get_config() -> dict[str, str]:
    global logger
    config: Dict[str, str] = {}

    #######
    # Parse command line args
    #######
    parser = argparse.ArgumentParser(description="Submit file(s) to Nemesis.", prog="submit_to_nemesis")
    parser.add_argument("-f", "--file", type=str, nargs="+", help="File(s) to submit to Nemesis")
    parser.add_argument("--folder", type=str, nargs="+", help="Folders(s) to submit to Nemesis")
    parser.add_argument("-m", "--monitor", type=str, nargs="?", help="Folder to monitor for new files")
    parser.add_argument("-s", "--sec_between_files", type=float, nargs="?", default=0, help="Seconds between file submissions (default 0). If > 0, it cannot be used with the --workers argument.")
    parser.add_argument("-w", "--workers", type=int, nargs="?", default=10, help="Number of workers to use (default 10). If --sec_between_files argument is set, value will be 1")
    parser.add_argument("-r", "--repeat", type=int, default=0, help="Times to repeat the submission (for stress testing)")
    parser.add_argument("-l", "--log_level", type=str, default="INFO", help="Log level (default INFO)")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="HTTP connect/read/write/pool timeout in seconds (default 60)")
    parser.add_argument("-c", "--cookies", type=int, help="Number of fake cookies to construct and generate.")
    if len(sys.argv) < 2:
        parser.print_usage()
        return None

    try:
        args = parser.parse_args()
    except SystemExit:
        return None

    #######
    # Load settings from config file
    #######
    script_folder = os.path.dirname(os.path.realpath(__file__))
    config_file_path = f"{script_folder}/submit_to_nemesis.yaml"

    if os.path.exists(config_file_path):
        with open(config_file_path, "rb") as f:
            config = yaml.safe_load(f)
    else:
        config["nemesis_url"] = ""
        while not config["nemesis_url"]:
            config["nemesis_url"] = input("Nemesis URL http://<NEMSIS_SERVER>:<PORT>/ : ")
            if not config["nemesis_url"].endswith("/"):
                config["nemesis_url"] = config["nemesis_url"] + "/"

        config["nemesis_creds"] = ""
        while not config["nemesis_creds"]:
            config["nemesis_creds"] = input("Nemesis creds <USER>:<PASSWORD> : ")

        config["operator_name"] = ""
        while not config["operator_name"]:
            config["operator_name"] = input("Operator name (required): ")
            config["operator_name"] = config["operator_name"].upper()

        config["project_name"] = ""
        while not config["project_name"]:
            config["project_name"] = input("Project name (required): ")
            config["project_name"] = config["project_name"].upper()

        config["network_name"] = ""
        if not config["network_name"]:
            config["network_name"] = input("Network name (optional): ")

        config["expiration_days"] = 100
        config["expiration_days"] = input("Days until data expiration (optional, default 100): ")
        while config["expiration_days"] and not config["expiration_days"].isnumeric():
            config["expiration_days"] = int(input("Days until data expiration (optional, default 100): "))
        if not config["expiration_days"]:
            config["expiration_days"] = 100
        config["expiration_days"] = int(config["expiration_days"])

        config["elasticsearch_url"] = ""
        while not config["elasticsearch_url"]:
            config["elasticsearch_url"] = input("Elasticsearch URL http://<ELASTIC_SERVER>:<PORT>/elastic/ : ")
            if config["elasticsearch_url"].endswith("/"):
                config["elasticsearch_url"] = config["elasticsearch_url"].rstrip("/")

        config["elasticsearch_creds"] = ""
        while not config["elasticsearch_creds"]:
            config["elasticsearch_creds"] = input("Elasticsearch creds <USER>:<PASSWORD> : ")

        with open(config_file_path, "w") as f:
            yaml.dump(config, f)

    nemesis_user, nemesis_pass = config["nemesis_creds"].split(":")
    config["nemesis_user"] = nemesis_user
    config["nemesis_pass"] = nemesis_pass

    config["file"] = args.file
    config["folder"] = args.folder
    config["monitor"] = args.monitor
    config["sec_between_files"] = args.sec_between_files
    config["repeat"] = args.repeat
    config["timeout"] = args.timeout
    config["log_level"] = args.log_level
    config["cookies"] = args.cookies

    configure_logger(EnvironmentSettings.DEVELOPMENT, config["log_level"], True)
    global logger
    logger = structlog.getLogger()
    logger.debug("Config", config=config)

    if args.sec_between_files > 0:
        if args.workers > 1:
            logger.warning("sec_between_files argument is set, workers will be set to 1")
        config["workers"] = 1
    else:
        config["workers"] = args.workers

    return config


async def get_timestamp(days_to_add=0):
    dt = datetime.now()

    if days_to_add != 0:
        dt = dt + timedelta(days=days_to_add)

    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


async def get_metadata(config: dict[str, str], data_type: str):
    metadata = {}
    metadata["agent_id"] = config["operator_name"]
    metadata["agent_type"] = "submit_to_nemesis"
    metadata["automated"] = False
    metadata["data_type"] = data_type
    # metadata["source"] = "computer.domain.com"
    metadata["expiration"] = await get_timestamp(config["expiration_days"])
    metadata["project"] = config["project_name"]
    metadata["timestamp"] = await get_timestamp()
    return metadata


api_client: httpx.AsyncClient = None


async def get_nemesis_api_client(config) -> httpx.AsyncClient:
    global api_client, logger
    if not api_client:
        nemesis_url = config["nemesis_url"]
        nemesis_user = config["nemesis_user"]
        nemesis_pass = config["nemesis_pass"]
        timeout = config["timeout"]

        auth = httpx.BasicAuth(nemesis_user, nemesis_pass)
        transport = httpx.AsyncHTTPTransport(retries=5, verify=False)
        limits = httpx.Limits(
            max_keepalive_connections=5,
            max_connections=10,
        )

        api_client = httpx.AsyncClient(
            base_url=nemesis_url,
            auth=auth,
            transport=transport,
            timeout=timeout,
            limits=limits
        )

    return api_client


async def nemesis_post_file(config: dict[str, str], file_path: str):
    """
    Takes a series of raw file bytes and POSTs it to the NEMESIS /file API endpoint.

    **Parameters**

    ``file_bytes``
        Bytes of the file we're uploading.

    **Returns**

    A new UUID string returned by the Nemesis API.
    """
    nemesis_url = config["nemesis_url"]

    client = NemesisApiClient(nemesis_url, await get_nemesis_api_client(config))
    # set a 15 minute upload timeout
    client.timeout = 60*15
    
    try:
        resp = await client.send_file(FileUploadRequest(file_path))
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.error("Nemesis API server returned 404 Not Found. Is the URL correct or is the API route enabled?", url=nemesis_url)
        else:
            logger.error(f"Nemesis API server returned {e.response.status_code}")
    except httpx.TimeoutException as e:
        timeoutStr = type(e).__name__
        logger.error(f"HTTP {timeoutStr} occured while making Nemesis API call", url=nemesis_url, timeout_type=timeoutStr)
        return None
    except httpx.ConnectError:
        logger.error("Unable to connect to Nemesis API server", url=nemesis_url)
        return None
    except PermissionError:
        logger.error("Access denied to file")
        return None
    except Exception as e:
        logger.exception(e, message="nemesis_post_file error")
        return None
    else:
        logger.debug(f"Uploaded file '{file_path}' to nemesis! File ID: {resp.object_id}. Sending file data message...")
        return resp.object_id


async def nemesis_post_data(config: dict[str, str], data):
    """
    Takes a json blob and POSTs it to the NEMESIS /data API endpoint.

    **Parameters**

    ``data``
        JSON formatted blob to post.

    **Returns**

    True if the request was successful, False otherwise.
    """

    client = await get_nemesis_api_client(config)

    resp = await client.post(NemesisApiClient.DATA_ENDPOINT, json=data)
    resp.raise_for_status()

    obj = resp.json()
    return obj


async def submit_random_cookies(config, num_cookies=1000) -> uuid.UUID | None:
    """
    Generates the specified number of cookies and submits the entire batch
    at once to Nemesis.
    """

    metadata = await get_metadata(config, "cookie")

    word_site = "https://www.mit.edu/~ecprice/wordlist.10000"
    response = requests.get(word_site)
    words = response.content.decode("utf-8").splitlines()
    domain = f"{'-'.join(random.choices(words, k=2))}.com"
    cookie_data = []

    for i in range(num_cookies):
        if i % 100 == 0:
            domain = f"{'-'.join(random.choices(words, k=2))}.com"
        cookie_data.append(
            {
                "user_data_directory": "C:/Users/harmj0y/AppData/Local/Google/Chrome/User Data/Default/Cookies",
                "domain": domain,
                "path": "/",
                "name": f"VALUE_{i}",
                "value": f"{random.choice(words)}_{random.randint(1, 10000000)}",
                "expires": "2030-01-01T01:01:01.000Z",
                "secure": True,
                "http_only": True,
                "session": False,
                "samesite": "lax",
                "source_port": 443,
            }
        )

    resp = await nemesis_post_data(config, {"metadata": metadata, "data": cookie_data})
    return uuid.UUID(resp["object_id"]) if resp else None


def string_matches_regexes(regexes: list[str], file_path: str) -> bool:
    """
    Returns True if the regex, False otherwise.
    """

    for matcher in regexes:
        if re.match(matcher, file_path):
            return True

    return False


async def post_json_to_api(config: dict[str, str], file_path: str) -> uuid.UUID | None:
    with open(file_path, "r") as f:
        services_json_raw = f.read()
        services_json = json.loads(services_json_raw)
        resp = await nemesis_post_data(config, services_json)

        if resp:
            logger.debug("File data sent to Nemesis", message_uuid=resp["object_id"], file_path=file_path)
            return uuid.UUID(resp["object_id"])
        else:
            return None


async def submit_file_with_raw_data_tag(config: dict[str, str], file_path: str, tags: List[str]) -> uuid.UUID | None:
    object_id = await nemesis_post_file(config, file_path)
    if not object_id:
        logger.error("No nemesis_file_id returned when uploading raw_data file", tags=tags, file_path=file_path)
        return None
    else:
        logger.debug("raw_data file uploaded to Nemesis", file_uuid=object_id, file_path=file_path)

    metadata = await get_metadata(config, "raw_data")

    raw_data = {}
    raw_data["tags"] = tags
    raw_data["data"] = object_id
    raw_data["is_file"] = True

    resp = await nemesis_post_data(config, {"metadata": metadata, "data": [raw_data]})
    if resp:
        logger.debug("raw_data file data sent to Nemesis", message_uuid=resp["object_id"], file_path=file_path, tags=tags)
        return uuid.UUID(resp["object_id"])
    else:
        return None


async def submit_file(config: dict[str, str], file_path: str) -> uuid.UUID | None:
    file_data = {}
    file_path = os.path.abspath(file_path)
    file_data["path"] = file_path

    file_data["size"] = os.path.getsize(file_path)

    object_id = await nemesis_post_file(config, file_path)
    if not object_id:
        return
    else:
        logger.debug("File uploaded to Nemesis", file_uuid=object_id, file_path=file_path)

    file_data["object_id"] = object_id
    metadata = await get_metadata(config, "file_data")

    # post to the Nemesis data API (`data` needs to be an array of dictionaries!)
    resp = await nemesis_post_data(config, {"metadata": metadata, "data": [file_data]})
    if resp:
        logger.debug("File data submitted to Nemesis", file_uuid=resp["object_id"], path=file_path)
        return uuid.UUID(resp["object_id"])
    else:
        return None


async def process_file(config: dict[str, str], file_path: str) -> uuid.UUID | None:
    """
    Takes a configuration dictionary and file path, and uploads the file to Nemesis depending on what the filename is.
    """
    api_json_regexes = [
        r".*authentication_data.*\.json$",
        r".*cookies.*\.json$",
        # r".*file_data.*\.json$",          # Removing for now since normal file uploads use this
        r".*file_information.*\.json$",
        r".*named_pipes.*\.json$",
        r".*network_connections.*\.json$",
        r".*path_list.*\.json$",
        r".*process_data.*\.json$",
        r".*registry_value.*\.json$",
        r".*services_api.*\.json$",  # NOTE: This must not conflict with the example Seatbelt services either
    ]

    dpapi_domain_backupkey_regex = r".*dpapi_domain_backupkey.*\.json$"
    seatbelt_json_regex = r".*seatbelt.*\.json$"
    bof_reg_collect_regex = r".*bof_reg_collect.*\.nemesis$"

    # Process files differently depending on how they're named
    if string_matches_regexes(api_json_regexes, file_path):
        return await post_json_to_api(config, file_path)
    elif string_matches_regexes([dpapi_domain_backupkey_regex], file_path):
        return await submit_file_with_raw_data_tag(config, file_path, ["dpapi_domain_backupkey"])
    elif string_matches_regexes([seatbelt_json_regex], file_path):
        return await submit_file_with_raw_data_tag(config, file_path, ["seatbelt_json"])
    elif string_matches_regexes([bof_reg_collect_regex], file_path):
        return await submit_file_with_raw_data_tag(config, file_path, ["bof_reg_collect"])
    else:
        # Default case: just upload the file
        return await submit_file(config, file_path)


async def process_folder(config, folder_path) -> AsyncIterator:
    """
    Processes all files in a folder.
    """

    if config["sec_between_files"] > 0:
        workers = 1
        logger.info("Processing files in folder synchronously", folder_path=folder_path, workers=1, sec_between_files=config["sec_between_files"])
    else:
        workers = config["workers"]
        logger.info("Processing files in folder concurrently", folder_path=folder_path, workers=config["workers"], sec_between_files=config["sec_between_files"])

    yield submit_paths_concurrently(config, folder_path, workers, config["sec_between_files"])


# Keep this global for now so we can cancel pending tasks during shutdown/global exceptions
pending = set()


async def limit_concurrency(aws: Iterator | AsyncIterator, limit: int) -> AsyncIterator:
    """Limits the concurrency of async functions.

    Graciously took this function from https://death.andgravity.com/limit-concurrency.

    Args:
        aws (Iterator | AsyncIterator): An iterator that produces values .
        limit (int): The maximum number of concurrent async tasks.

    Yields:
        AsyncIterator: An iterator that produces values at a rate defined by the limit.
    """
    global pending

    try:
        aws = aiter(aws)  # type: ignore
        is_async = True
    except TypeError:
        aws = iter(aws)  # type: ignore
        is_async = False

    aws_ended = False

    while pending or not aws_ended:
        while len(pending) < limit and not aws_ended:
            try:
                aw = await anext(aws) if is_async else next(aws)  # type: ignore
            except StopAsyncIteration if is_async else StopIteration:
                aws_ended = True
            else:
                pending.add(asyncio.ensure_future(aw))

        if not pending:
            return

        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        while done:
            yield done.pop()


async def map_unordered(func: Callable, iterable: Iterator | AsyncIterator, limit=10) -> AsyncIterator:
    """Runs an async function over an iterable, limiting the number of async tasks that run concurrently.

    Ref - https://death.andgravity.com/limit-concurrency#async-iterables

    Args:
        func (Callable): Function to execution on each item in the iterable.
        iterable (Iterator | AsyncIterator): Generator function that produces values.
        limit (int, optional): The maximum number of concurrent async tasks. Defaults to 10.

    Yields:
        AsyncIterator: The result of the async function

    Examples:
        Examples should be written in doctest format, and should illustrate how
        to use the function.

        >>> async def async_print(arg):
                print("in async_print", arg)
                return arg


            async def main():
                async for result in map_unordered(async_print, range(1), 1):
                    await asyncio.sleep(0.1)
                    print("got result")


            if __name__ == "__main__":
                asyncio.run(main())
    """
    try:
        aws = map(func, iterable)
    except TypeError:
        aws = (func(x) async for x in iterable)

    async for task in limit_concurrency(aws, limit):
        yield await task


# Ref - https://death.andgravity.com/limit-concurrency#async-iterables
def return_args_and_exceptions(func, exception_handler: Callable) -> Callable:
    async def _return_args_and_exceptions(func, *args) -> Tuple[Any, Any, Optional[Exception]]:
        try:
            return *args, await func(*args)
        except Exception as e:
            exception_handler(e, args)
            return *args, e

    return functools.partial(_return_args_and_exceptions, func)


def exception_handler(e, args):
    logger.exception("Error processing file", args=args)


async def submit_paths_concurrently(config: dict[str, str], paths: List[str], workers: int, delay: float = 0) -> AsyncIterator[Tuple[str, uuid.UUID]]:
    """Submits files to Nemesis concurrently.

    Args:
        config (_type_): submit_to_nemesis configuration object.
        paths (List[str]): List of file or folder paths to submit to Nemesis.
        workers (int): Number of concurrent tasks that can run at once.
        delay (float, optional): Time delay between each submission. Defaults to 0.

    Returns:
        AsyncIterator[Tuple[str, uuid.UUID]]: _description_

    Yields:
        Iterator[AsyncIterator[Tuple[str, uuid.UUID]]]: _description_
    """
    total_file_count = 0
    result_count = 0

    def get_files():
        nonlocal total_file_count
        global logger

        for path in paths:
            # get the absolute path
            path = os.path.abspath(path)
            # Check if the path exists
            if not os.path.exists(path):
                logger.error("Path does not exist", path=path)
                continue

            if os.path.isfile(path):
                total_file_count += 1
                yield path
            else:
                for file_path in filter(os.path.isfile, glob.glob(path + "/**/*", recursive=True)):
                    total_file_count += 1

                for file_path in filter(os.path.isfile, glob.glob(path + "/**/*", recursive=True)):
                    yield file_path

    async def process_file_local(file_path) -> uuid.UUID | None:
        structlog.contextvars.bind_contextvars(
            file_path=file_path,
        )

        logger.info("Processing file")

        file_uuid = await process_file(config, file_path)

        logger.info(
            f"Done processing file {result_count+1}/{total_file_count}",
            file_uuid=str(file_uuid),
            total_completed=result_count + 1,
            total_file_count=total_file_count,
        )
        structlog.contextvars.clear_contextvars()

        if delay > 0:
            await asyncio.sleep(delay)

        return file_uuid

    wrapped_process_file = return_args_and_exceptions(process_file_local, exception_handler)

    try:
        async for result in map_unordered(wrapped_process_file, get_files(), limit=workers):
            result_count += 1
            yield result
    except asyncio.CancelledError:
        logger.warn("Cancelled file uploads")

    logger.info(f"Completed processing {result_count} files out of {total_file_count} total files")


async def wait_for_stable_size(file_path, delay=1.0, retries=600):
    logger.debug("Waiting for file size to stabilize", path=file_path)

    previous_size = -1
    current_size = 0
    tries = 0
    while tries < retries:
        try:
            current_size = os.path.getsize(file_path)
            if current_size == previous_size:
                return True
            previous_size = current_size
            await asyncio.sleep(delay)
            tries += 1
        except Exception as e:
            logger.error("Error accessing a newly create file", path=file_path, exception=e)
            return False
    return False


async def monitor_submit_paths_concurrently(config, path_iter: AsyncIterator, workers: int, delay: float = 0) -> AsyncIterator[Tuple[str, uuid.UUID]]:
    """Submits files to Nemesis concurrently.

    Args:
        config (_type_): submit_to_nemesis configuration object.
        paths (List[str]): List of file or folder paths to submit to Nemesis.
        workers (int): Number of concurrent tasks that can run at once.
        delay (float, optional): Time delay between each submission. Defaults to 0.

    Returns:
        AsyncIterator[Tuple[str, uuid.UUID]]: _description_

    Yields:
        Iterator[AsyncIterator[Tuple[str, uuid.UUID]]]: _description_
    """
    result_count = 0

    async def monitor_process_file_local(file_path) -> uuid.UUID | None:
        global logger

        structlog.contextvars.bind_contextvars(
            file_path=file_path,
        )

        logger.info("Processing file")

        if not await wait_for_stable_size(file_path):
            logger.error("An error occurred while waiting for the file. File did not process.", path=file_path)
            return

        file_uuid = await process_file(config, file_path)

        logger.info(
            f"Done processing file {result_count+1}",
            file_uuid=str(file_uuid),
            total_completed=result_count + 1,
        )
        structlog.contextvars.clear_contextvars()

        if delay > 0:
            await asyncio.sleep(delay)

        return file_uuid

    wrapped_process_file = return_args_and_exceptions(monitor_process_file_local, exception_handler)

    try:
        async for result in map_unordered(wrapped_process_file, path_iter, limit=workers):
            result_count += 1
            yield result
    except asyncio.CancelledError:
        logger.warn("Cancelled file uploads")

    logger.info(f"Completed processing {result_count} total files")


async def is_file_processed(es_client, message_id: int):
    query = {"bool": {"filter": [{"match_phrase": {"metadata.messageId": message_id}}]}}

    try:
        resp = es_client.search(index="file_data_enriched", query=query, source=True, source_includes=["objectId"])
        hits = resp["hits"]["hits"]
        if len(hits) == 0:
            return False
        else:
            return True
    except Exception as e:
        print(f"[!] Exception querying Elastic: {e}")
        return False


async def submit_files_and_folders(config: dict[str, str]):
    paths_to_process = []
    processed_file_uuids = []

    logger.info("Submitting files/folders to Nemesis")
    if config["file"]:
        for f in config["file"]:
            paths_to_process.append(f)

    if config["folder"]:
        for f in config["folder"]:
            paths_to_process.append(f)

    for i in range(config["repeat"] + 1):
        logger.info("Waiting for tasks to complete")
        async for result in submit_paths_concurrently(config, paths_to_process, config["workers"], config["sec_between_files"]):
            path, file_uuid = result
            processed_file_uuids.append(file_uuid)


async def monitor_and_submit_folder_files(config: dict[str, str], loop):
    processed_file_uuids = []

    path = os.path.abspath(config["monitor"])

    if not os.path.exists(path):
        logger.error("Path does not exist", path=path)
        return

    if os.path.isfile(path):
        logger.error("The monitor path is a file, not a folder", path=path)

    logger.info("Monitoring a folder for new files to submit", path=path)

    iter = monitor_directory(path, loop)
    async for result in monitor_submit_paths_concurrently(config, iter, config["workers"], config["sec_between_files"]):
        path, file_uuid = result
        processed_file_uuids.append(file_uuid)


async def amain(loop):
    config = await get_config()
    if not config:
        return

    try:
        if config["cookies"]:
            await submit_random_cookies(config, config["cookies"])
        elif config["file"] or config["folder"]:
            await submit_files_and_folders(config)
        elif config["monitor"]:
            await monitor_and_submit_folder_files(config, loop)

    except asyncio.CancelledError:
        pass

    # Currently commented out since it has a bug since not all files go all the way through the file enrichment pipeline, so it'll hang on exit. Also isn't async
    # es_user, es_pass = config["elasticsearch_creds"].split(":"
    # es_client = Elasticsearch(config["elasticsearch_url"], basic_auth=(es_user, es_pass), verify_certs=False, ssl_show_warn=False)
    # # while len(processed_file_uuids) > 0:
    #     time.sleep(1)
    #     for file_uuid in processed_file_uuids:
    #         processed = await is_file_processed(es_client, file_uuid)
    #         if processed:
    #             processed_file_uuids.remove(file_uuid)

    # logger.info(f"Processed {num_files_submitted} files in {datetime.now() - start_time}\n")
