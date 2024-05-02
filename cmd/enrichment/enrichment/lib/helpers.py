# Standard Libraries
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import uuid
import zipfile
import zlib
from dataclasses import dataclass
from enum import Enum
from io import SEEK_END
from typing import List, Optional

# 3rd Party Libraries
import aiosqlite
import libarchive
import magic
import nemesispb.nemesis_pb2 as pb
import py7zr
import structlog
import yara
from google.protobuf.json_format import ParseDict
from impacket.dpapi import (DPAPI_BLOB, CredHist, DomainKey, MasterKey,
                            MasterKeyFile)
from impacket.uuid import bin_to_string
from nemesiscommon.messaging import MessageQueueProducerInterface

logger = structlog.get_logger(module=__name__)


##################################################
#
# Chromium helpers
#
# TODO: make these all async?
#
##################################################


# from https://source.chromium.org/chromium/chromium/src/+/main:components/download/public/common/download_danger_type.h
class DangerType(Enum):
    NOT_DANGEROUS = 0
    DANGEROUS_FILE = 1
    DANGEROUS_URL = 2
    DANGEROUS_CONTENT = 3
    MAYBE_DANGEROUS_CONTENT = 4
    UNCOMMON_CONTENT = 5
    USER_VALIDATED = 6
    DANGEROUS_HOST = 7
    POTENTIALLY_UNWANTED = 8
    ALLOWLISTED_BY_POLICY = 9
    ASYNC_SCANNING = 10
    BLOCKED_PASSWORD_PROTECTED = 11
    BLOCKED_TOO_LARGE = 12
    SENSITIVE_CONTENT_WARNING = 13
    SENSITIVE_CONTENT_BLOCK = 14
    DEEP_SCANNED_SAFE = 15
    DEEP_SCANNED_OPENED_DANGEROUS = 16
    PROMPT_FOR_SCANNING = 17
    BLOCKED_UNSUPPORTED_FILETYPE = 18
    DANGEROUS_ACCOUNT_COMPROMISE = 19


@dataclass
class ChromiumFilePath:
    file_path: str  # the full file path
    success: bool = False  # true/false if parsing was successful or not
    user_data_directory: Optional[str] = None  # user directory path
    file_type: Optional[str] = None  # history, logins, cookies, state
    browser: Optional[str] = None  # Edge, Chrome, etc., extracted from the file path
    username: Optional[str] = None  # username, extracted from the file path


def parse_chromium_file_path(file_path: str) -> ChromiumFilePath:
    """
    Checks if a file path is a Chromium file (Cookies, Login Data, History, or Local State)
    and returns a ChromiumFilePath object.
    """

    chromium_file_path = ChromiumFilePath(file_path)

    regex1 = re.compile(".*/(?P<username>.*)/AppData/Local/(Google|Microsoft|BraveSoftware)/(?P<browser>Chrome|Edge|Brave-Browser)/User Data/(?P<profile>.+/)?(?P<type>Local State|History|Login Data|Cookies|Network/Cookies)$")
    matches1 = regex1.search(file_path, re.IGNORECASE)

    if matches1:
        # Chrome/Edge/Brave being normal
        chromium_file_path.success = True
        chromium_file_path.username = matches1.group("username").lower()
        chromium_file_path.browser = matches1.group("browser").split("-")[0].lower()

        loc = file_path.find("/User Data/") + len("/User Data/")
        chromium_file_path.user_data_directory = file_path[0:loc]

        match matches1.group("type"):
            case "Local State":
                chromium_file_path.file_type = "state"
            case "History":
                chromium_file_path.file_type = "history"
            case "Login Data":
                chromium_file_path.file_type = "logins"
            case "Cookies":
                chromium_file_path.file_type = "cookies"
            case "Network/Cookies":
                chromium_file_path.file_type = "cookies"
    else:
        # stupid Opera being a special case
        regex2 = re.compile(".*/(?P<username>.*)/AppData/Roaming/Opera Software/Opera Stable/(?P<type>Local State|History|Login Data|Cookies|Network/Cookies)$")
        matches2 = regex2.search(file_path)

        if matches2:
            chromium_file_path.success = True
            chromium_file_path.username = matches2.group("username").lower()
            chromium_file_path.browser = "opera"

            loc = file_path.find("/Opera Stable/") + len("/Opera Stable/")
            chromium_file_path.user_data_directory = file_path[0:loc]

            match matches2.group("type"):
                case "Local State":
                    chromium_file_path.file_type = "state"
                case "History":
                    chromium_file_path.file_type = "history"
                case "Login Data":
                    chromium_file_path.file_type = "logins"
                case "Cookies":
                    chromium_file_path.file_type = "cookies"
                case "Network/Cookies":
                    chromium_file_path.file_type = "cookies"

    return chromium_file_path


def convert_chromium_timestamp_to_datetime(timestamp: int) -> datetime.datetime:
    """Converts a Chromium timestamp value to datetime."""
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp)


def convert_epoch_seconds_to_datetime(timestamp: float) -> datetime.datetime:
    """Converts epoch seconds to a datetime."""
    return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=timestamp)


async def process_chromium_history(
    object_id: str,
    file_path: str,
    metadata: pb.Metadata,
    parsed_data: pb.ParsedData,
    chromium_history_q: MessageQueueProducerInterface,
    chromium_downloads_q: MessageQueueProducerInterface,
) -> None:
    """
    Helper that parses out the appropriate data from the "history" and "downloads"
    tables from a Chromium `History` file, builds the appropriate protobuf messages,
    and publishes them to the passed queues.

    TODO: do we need to chunk up the URLs into some batch size?
    """
    async with aiosqlite.connect(file_path) as db:
        # first parse out all of the url entries and emit one or more ChromiumHistoryMessage protobufs
        async with db.execute("SELECT url,title,visit_count,typed_count,last_visit_time FROM urls") as cursor:
            chromium_history_message = pb.ChromiumHistoryMessage()
            chromium_history_message.metadata.CopyFrom(metadata)
            page_size = 1000
            total_history_urls = 0
            counter = 0
            start = time.time()

            async for row in cursor:
                history_entry = pb.ChromiumHistoryEntry()

                history_entry.originating_object_id = object_id
                history_entry.user_data_directory = parsed_data.chromium_history.user_data_directory
                history_entry.username = parsed_data.chromium_history.username
                history_entry.browser = parsed_data.chromium_history.browser

                (
                    history_entry.url,
                    history_entry.title,
                    history_entry.visit_count,
                    history_entry.typed_count,
                    last_visit_time,
                ) = row

                last_visit_time_dt = convert_chromium_timestamp_to_datetime(last_visit_time)
                history_entry.last_visit_time.FromDatetime(last_visit_time_dt)

                chromium_history_message.data.append(history_entry)
                counter += 1
                total_history_urls += 1

                if counter >= page_size:
                    # send the existing 1000 packaged entries
                    await chromium_history_q.Send(chromium_history_message.SerializeToString())
                    # clear out the data field
                    chromium_history_message.ClearField('data')
                    counter = 0

            if len(chromium_history_message.data) > 0:
                # send any leftovers
                await chromium_history_q.Send(chromium_history_message.SerializeToString())

            end = time.time()
            await logger.ainfo(f"{total_history_urls} Chromium history URLs processed in in {(end - start):.2f} seconds", object_id=object_id)

        # first parse out all of the downloads and emit one or more ChromiumDownloadMessage protobufs
        async with db.execute("SELECT tab_url,target_path,start_time,end_time,total_bytes,danger_type FROM downloads") as cursor:
            chromium_download_message = pb.ChromiumDownloadMessage()
            chromium_download_message.metadata.CopyFrom(metadata)
            page_size = 1000
            total_downloads = 0
            counter = 0
            start = time.time()

            async for row in cursor:
                download = pb.ChromiumDownload()

                download.originating_object_id = object_id
                download.user_data_directory = parsed_data.chromium_history.user_data_directory
                download.username = parsed_data.chromium_history.username
                download.browser = parsed_data.chromium_history.browser

                (
                    download.url,
                    download_path,
                    start_time,
                    end_time,
                    download.total_bytes,
                    danger_type,
                ) = row

                download.download_path = download_path.replace("\\", "/")
                start_time_dt = convert_chromium_timestamp_to_datetime(start_time)
                end_time_dt = convert_chromium_timestamp_to_datetime(end_time)
                download.start_time.FromDatetime(start_time_dt)
                download.end_time.FromDatetime(end_time_dt)
                download.danger_type = DangerType(danger_type).name

                chromium_download_message.data.append(download)
                counter += 1
                total_downloads += 1

                if counter >= page_size:
                    # send the existing 1000 packaged entries
                    await chromium_downloads_q.Send(chromium_download_message.SerializeToString())
                    # clear out the data field
                    chromium_download_message.ClearField('data')
                    counter = 0

            if len(chromium_history_message.data) > 0:
                # send any leftovers
                await chromium_downloads_q.Send(chromium_download_message.SerializeToString())

            end = time.time()
            await logger.ainfo(f"{total_downloads} Chromium downloads processed in in {(end - start):.2f} seconds", object_id=object_id)


async def process_chromium_logins(object_id: str, file_path: str, metadata: pb.Metadata, parsed_data: pb.ParsedData, chromium_logins_q: MessageQueueProducerInterface) -> None:
    """
    Helper that parses out the appropriate data from the "logins" table from a
    Chromium `Login Data` file, builds the appropriate protobuf messages, and publishes
    them to the passed queue.
    """
    async with aiosqlite.connect(file_path) as db:
        # first parse out all of the url entries and emit one or more ChromiumLoginMessage protobufs
        async with db.execute("SELECT origin_url,username_value,CAST(password_value as BLOB),signon_realm,date_created,date_last_used,date_password_modified,times_used FROM logins") as cursor:
            chromium_login_message = pb.ChromiumLoginMessage()
            chromium_login_message.metadata.CopyFrom(metadata)

            async for row in cursor:
                login = pb.ChromiumLogin()

                login.masterkey_guid = "00000000-0000-0000-0000-000000000000"  # default null for UUID
                login.originating_object_id = object_id
                login.user_data_directory = parsed_data.chromium_logins.user_data_directory
                login.username = parsed_data.chromium_logins.username
                login.browser = parsed_data.chromium_logins.browser

                (
                    login.origin_url,
                    login.username_value,
                    login.password_value_enc,
                    login.signon_realm,
                    date_created,
                    date_last_used,
                    date_password_modified,
                    times_used,
                ) = row

                if times_used is not None:
                    login.times_used = times_used

                if len(login.password_value_enc) > 0:
                    if login.password_value_enc.startswith(b"v10"):
                        login.encryption_type = "aes"
                    else:
                        blob = await parse_dpapi_blob(login.password_value_enc)
                        if blob.success:
                            login.encryption_type = "dpapi"
                            login.masterkey_guid = blob.dpapi_master_key_guid
                        else:
                            login.encryption_type = "unknown"
                else:
                    login.encryption_type = "unknown"

                date_created_dt = convert_chromium_timestamp_to_datetime(date_created)
                login.date_created.FromDatetime(date_created_dt)
                date_last_used_dt = convert_chromium_timestamp_to_datetime(date_last_used)
                login.date_last_used.FromDatetime(date_last_used_dt)
                date_password_modified_dt = convert_chromium_timestamp_to_datetime(date_password_modified)
                login.date_password_modified.FromDatetime(date_password_modified_dt)

                chromium_login_message.data.append(login)

            await chromium_logins_q.Send(chromium_login_message.SerializeToString())


async def is_chromium_cookie_json(file_path: str) -> bool:
    """
    Helper that downloads the specified file and tries to load it as a json,
    checking various fields to see if it's likely a Chromium cookie json dump.
    """
    try:
        with open(file_path, "r") as f:
            file_json = json.loads(f.read())
            if type(file_json) == list and len(file_json) > 0:
                if type(file_json[0]) == dict and len(file_json[0]) > 10 and len(file_json[0]) < 20:
                    fields = list(file_json[0].keys())
                    if "name" in fields and "domain" in fields and "sameSite" in fields and "httpOnly" in fields:
                        return True
            return False
    except:
        return False


async def process_chromium_cookies(object_id: str, file_path: str, metadata: pb.Metadata, parsed_data: pb.ParsedData, chromium_cookies_q: MessageQueueProducerInterface) -> None:
    """
    Helper that parses out the appropriate data from the "cookies" table from a
    Chromium `Login Data` file, builds the appropriate protobuf messages, and publishes
    them to the passed queue.
    """
    async with aiosqlite.connect(file_path) as db:
        # first parse out all of the url entries and emit one or more ChromiumLoginMessage protobufs
        async with db.execute("SELECT host_key,name,path,creation_utc,expires_utc,last_access_utc,last_update_utc,is_secure,is_httponly,is_persistent,samesite,source_port,CAST(encrypted_value as BLOB) FROM cookies") as cursor:
            chromium_cookie_message = pb.ChromiumCookieMessage()
            chromium_cookie_message.metadata.CopyFrom(metadata)

            async for row in cursor:
                cookie = pb.ChromiumCookie()

                cookie.masterkey_guid = "00000000-0000-0000-0000-000000000000"  # default null for UUID
                cookie.originating_object_id = object_id
                cookie.user_data_directory = parsed_data.chromium_cookies.user_data_directory
                cookie.username = parsed_data.chromium_cookies.username
                cookie.browser = parsed_data.chromium_cookies.browser

                (
                    host_key,
                    cookie.name,
                    cookie.path,
                    creation_utc,
                    expires_utc,
                    last_access_utc,
                    last_update_utc,
                    cookie.is_secure,
                    cookie.is_httponly,
                    is_persistent,
                    samesite,
                    cookie.source_port,
                    cookie.value_enc,
                ) = row

                cookie.host_key = host_key.lstrip(".").lower()
                cookie.is_session = not is_persistent

                match samesite:
                    case 0:
                        cookie.samesite = "NONE"
                    case 1:
                        cookie.samesite = "LAX"
                    case 2:
                        cookie.samesite = "STRICT"
                    case _:
                        cookie.samesite = "UNKNOWN"

                if len(cookie.value_enc) > 0:
                    if cookie.value_enc.startswith(b"v10"):
                        cookie.encryption_type = "aes"
                    else:
                        blob = await parse_dpapi_blob(cookie.value_enc)
                        if blob.success:
                            cookie.encryption_type = "dpapi"
                            cookie.masterkey_guid = blob.dpapi_master_key_guid
                        else:
                            cookie.encryption_type = "unknown"
                else:
                    cookie.encryption_type = "unknown"

                creation_dt = convert_chromium_timestamp_to_datetime(creation_utc)
                cookie.creation.FromDatetime(creation_dt)
                expires_dt = convert_chromium_timestamp_to_datetime(expires_utc)
                cookie.expires.FromDatetime(expires_dt)
                last_access_dt = convert_chromium_timestamp_to_datetime(last_access_utc)
                cookie.last_access.FromDatetime(last_access_dt)
                last_update_dt = convert_chromium_timestamp_to_datetime(last_update_utc)
                cookie.last_update.FromDatetime(last_update_dt)

                chromium_cookie_message.data.append(cookie)

            await chromium_cookies_q.Send(chromium_cookie_message.SerializeToString())


async def process_cookies_json(object_id: str, file_path: str, metadata: pb.Metadata, parsed_data: pb.ParsedData, chromium_cookies_q: MessageQueueProducerInterface) -> None:
    """
    Helper that parses out the appropriate data from a (likely Chromium) cookies JSON, builds
    the appropriate protobuf messages, and publishes them to the passed queue.
    """

    try:
        with open(file_path, "r") as f:
            cookie_json_all = json.loads(f.read())

        cookie_message = pb.ChromiumCookieMessage()
        cookie_message.metadata.CopyFrom(metadata)

        for cookie_json in cookie_json_all:
            try:
                cookie = pb.ChromiumCookie()

                # user_data_directory is not known here

                cookie.originating_object_id = object_id
                cookie.host_key = cookie_json["domain"].lower()
                cookie.path = cookie_json["path"]
                cookie.name = cookie_json["name"]
                cookie.is_decrypted = True
                cookie.value_dec = cookie_json["value"]

                expires_raw = 0
                if "expires" in cookie_json:
                    expires_raw = cookie_json["expires"]
                elif "expirationDate" in cookie_json:
                    expires_raw = cookie_json["expirationDate"]
                expires_dt = convert_epoch_seconds_to_datetime(expires_raw)
                cookie.expires.FromDatetime(expires_dt)

                if "httpOnly" in cookie_json:
                    cookie.is_httponly = cookie_json["httpOnly"]

                if "sameSite" in cookie_json:
                    if cookie_json["sameSite"].upper() == "NONE":
                        cookie.samesite = "NONE"
                    elif cookie_json["sameSite"].upper() == "LAX":
                        cookie.samesite = "LAX"
                    elif cookie_json["sameSite"].upper() == "STRICT":
                        cookie.samesite = "STRICT"
                    else:
                        cookie.samesite = "UNKNOWN"

                if "session" in cookie_json:
                    cookie.is_session = cookie_json["session"]

                if "secure" in cookie_json:
                    cookie.is_secure = cookie_json["secure"]

                if "sourcePort" in cookie_json:
                    cookie.source_port = cookie_json["sourcePort"]

                cookie_message.data.append(cookie)

            except Exception as e:
                await logger.awarning(f"Error parsing a specific cookie in process_chromium_cookies_json: {e}")

        await chromium_cookies_q.Send(cookie_message.SerializeToString())

    except Exception as e:
        await logger.aerror(f"Error in process_chromium_cookies_json: {e}")


##################################################
#
# DPAPI helpers
#
# TODO: make these async?
#
##################################################


def parse_masterkey_file_path(file_path_orig: str) -> dict:
    """
    Checks if a file path is a masterkey file, returning the username,
    user SID, and masterkey file GUID if the path matches, as well
    as true if the file is a machine path.

    If the file does not match a masterkey path, "None" is returned.
    """

    user_masterkey_regex = (
        ".*/(?P<username>[\w\. -]+)/AppData/Roaming/Microsoft/Protect/(?P<sid>S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3})/.*(?P<guid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
    )
    machine_masterkey_regex = ".*/System32/Microsoft/Protect/(?P<sid>S-1-[0-59]-[0-9\-]+)/.*(?P<guid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"

    user_pattern = re.compile(user_masterkey_regex)
    user_matches = user_pattern.search(file_path_orig)

    if user_matches:
        return {
            "username": user_matches.group("username"),
            "sid": user_matches.group("sid"),
            "guid": user_matches.group("guid"),
            "is_machine_path": False,
        }
    else:
        machine_pattern = re.compile(machine_masterkey_regex)
        machine_matches = machine_pattern.search(file_path_orig)

        if machine_matches:
            return {"username": "", "sid": machine_matches.group("sid"), "guid": machine_matches.group("guid"), "is_machine_path": True}
        else:
            return {}


def parse_masterkey_file(data):
    """Parses DPAPI masterkey bytes to its masterkey and domainkey components.

    Returns a DpapiMasterkey protobuf.
    """

    try:
        dpapi_masterkey = pb.DpapiMasterkey()
        mkf = MasterKeyFile(data)
        dpapi_masterkey.masterkey_guid = mkf["Guid"].decode("UTF-16-LE")

        data = data[len(mkf) :]
        masterkey_len = mkf["MasterKeyLen"]
        backupkey_len = mkf["BackupKeyLen"]
        credhist_len = mkf["CredHistLen"]
        domainkey_len = mkf["DomainKeyLen"]

        if mkf["MasterKeyLen"] > 0:
            mk = MasterKey(data[:masterkey_len])
            dpapi_masterkey.masterkey_bytes = data[:masterkey_len]
            data = data[len(mk) :]

        if mkf["BackupKeyLen"] > 0:
            bkmk = MasterKey(data[:backupkey_len])
            data = data[len(bkmk) :]

        if mkf["CredHistLen"] > 0:
            ch = CredHist(data[:credhist_len])
            data = data[len(ch) :]

        if domainkey_len > 0:
            dk = DomainKey(data[:domainkey_len])
            dpapi_masterkey.domain_backupkey_guid = bin_to_string(dk["Guid"]).lower()
            dpapi_masterkey.domainkey_pb_secret = dk["SecretData"]
            data = data[len(dk) :]

        return dpapi_masterkey

    except:
        return None


def process_masterkey_file(object_id, file_path, file_path_orig, metadata):
    """
    Takes a Nemesis UUID representing a downloaded masterkey file, the
    original file path (to extract the username/SID), and the metadata for
    the file, parses the masterkey file, and returns a pb.DpapiMasterkeyMessage.
    """

    parsed_path = parse_masterkey_file_path(file_path_orig)

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    dpapi_masterkey = parse_masterkey_file(file_bytes)

    if dpapi_masterkey:
        dpapi_masterkey.object_id = object_id

        if parsed_path and "username" in parsed_path:
            dpapi_masterkey.username = parsed_path["username"]

        if parsed_path and "sid" in parsed_path:
            dpapi_masterkey.user_sid = parsed_path["sid"]

        # determine the "type" of this masterkey based on the path + presence of a domain backup key
        if parsed_path and "is_machine_path" in parsed_path and parsed_path["is_machine_path"]:
            dpapi_masterkey.type = "machine"
        elif dpapi_masterkey.domainkey_pb_secret:
            dpapi_masterkey.type = "domain_user"
        else:
            dpapi_masterkey.type = "local_user"

        dpapi_masterkey.is_decrypted = False

        return dpapi_masterkey


@dataclass
class ParsedDpapiBlob:
    dpapi_master_key_guid: Optional[str] = str
    dpapi_data: Optional[bytes] = None
    success: bool = False  # true/false if parsing was successful or not


async def parse_dpapi_blob(blob_bytes: bytes) -> ParsedDpapiBlob:
    """Async Helper that parses a single DPAPI blob to a dict of {dpapi_master_key_guid, dpapi_data}"""

    parsed_blob = ParsedDpapiBlob()

    try:
        # it's a bit tricky to carve _just_ the DPAPI blob, but this is how:
        blob = DPAPI_BLOB(blob_bytes)
        if blob.rawData is not None:
            blob.rawData = blob.rawData[: len(blob.getData())]
            parsed_blob.dpapi_master_key_guid = bin_to_string(blob["GuidMasterKey"]).lower()
            parsed_blob.dpapi_data = blob.rawData
            parsed_blob.success = True
    except Exception as e:
        await logger.awarning(f"Error in parse_dpapi_blob: {e}")

    return parsed_blob


def parse_dpapi_blob_sync(blob_bytes: bytes) -> ParsedDpapiBlob:
    """Non-aysnc Helper that parses a single DPAPI blob to a dict of {dpapi_master_key_guid, dpapi_data}"""

    parsed_blob = ParsedDpapiBlob()

    try:
        # it's a bit tricky to carve _just_ the DPAPI blob, but this is how:
        blob = DPAPI_BLOB(blob_bytes)
        if blob.rawData is not None:
            blob.rawData = blob.rawData[: len(blob.getData())]
            parsed_blob.dpapi_master_key_guid = bin_to_string(blob["GuidMasterKey"]).lower()
            parsed_blob.dpapi_data = blob.rawData
            parsed_blob.success = True
    except Exception as e:
        logger.warning(f"Error in parse_dpapi_blob_sync: {e}")

    return parsed_blob


async def carve_dpapi_blobs_from_bytes_helper(raw_bytes: bytes, file_name: str = "", nemesis_uuid: str = "") -> List[ParsedDpapiBlob]:
    """
    Helper that _just_ carves raw DPAPI blobs from bytes,
    returning a list of dicts {dpapi_master_key_guid, dpapi_data}
    """
    dpapi_blobs = list()
    dpapi_signature = b"\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\xC0\x4F\xC2\x97\xEB"

    # The following are potential base64 representations of the DPAPI provider GUID
    #   Generated by putting dpapiProviderGuid into the script here: https://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/
    dpapi_b64_signatures = [b"AAAA0Iyd3wEV0RGMegDAT8KX6", b"AQAAANCMnd8BFdERjHoAwE/Cl+", b"EAAADQjJ3fARXREYx6AMBPwpfr"]

    current_pos = 0
    loc = raw_bytes.find(dpapi_signature)
    while loc != -1:
        current_pos = loc
        # parse the blob so we get the masterkey GUID and carve the data into one blob
        try:
            blob = await parse_dpapi_blob(raw_bytes[current_pos:])
            if not blob.success:
                if file_name != "" and nemesis_uuid != "":
                    await logger.awarning("carve_dpapi_blobs_from_bytes: blob.rawData is None", file_name=file_name, nemesis_uuid=nemesis_uuid)
                else:
                    await logger.awarning("carve_dpapi_blobs_from_bytes: blob.rawData is None")
                current_pos += 1
            elif blob.dpapi_data:
                current_pos += len(blob.dpapi_data)
                dpapi_blobs.append(blob)
        except Exception as e:
            if file_name != "":
                await logger.awarning(f"exception parsing file {file_name} for dpapi blobs: {e}")
            else:
                await logger.awarning(f"exception parsing bytes for dpapi blobs: {e}")
            return dpapi_blobs
        loc = raw_bytes.find(dpapi_signature, current_pos)

    # check for our b64 signatures
    for dpapi_b64_signature in dpapi_b64_signatures:
        loc = raw_bytes.find(dpapi_b64_signature, current_pos)
        while loc != -1:
            end_loc = loc
            # try to check for the end of the base64 string
            for i in range(loc, len(raw_bytes)):
                if raw_bytes[i] not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=":
                    end_loc = i
                    break
            if end_loc != loc:
                try:
                    dpapi_blob_raw = base64.b64decode(raw_bytes[loc:end_loc])
                    blob = await parse_dpapi_blob(dpapi_blob_raw)
                    current_pos += end_loc - loc
                    if not blob.success:
                        await logger.awarning("carve_dpapi_blobs: blob.rawData is None", file_name=file_name, nemesis_uuid=nemesis_uuid)
                    elif blob.dpapi_data:
                        dpapi_blobs.append(blob)
                except Exception as e:
                    if file_name != "":
                        await logger.awarning(f"exception parsing file {file_name} for b64dpapi blobs: {e}")
                    else:
                        await logger.awarning(f"exception parsing bytes for dpapi blobs: {e}")
                    return dpapi_blobs
            loc = raw_bytes.find(dpapi_b64_signature, current_pos)

    return dpapi_blobs


async def carve_dpapi_blobs_from_file_helper(file_name: str, nemesis_uuid: str) -> List[ParsedDpapiBlob]:
    """
    Helper that _just_ carves raw DPAPI blobs from a file,
    returning a list of dicts {dpapi_master_key_guid, dpapi_data}
    """

    dpapi_blobs = list()
    chunk_size = 512000

    with open(file_name, "rb") as f:
        # chunking to handle large files
        while chunk := f.read(chunk_size):
            dpapi_blobs += await carve_dpapi_blobs_from_bytes_helper(chunk, file_name, nemesis_uuid)

    return dpapi_blobs


async def carve_dpapi_blobs_from_file(file_name: str, nemesis_uuid: str, metadata: pb.Metadata) -> Optional[tuple[list[str], list[pb.DpapiBlobMessage]]]:
    """Carves dpapi blobs from a binary file.

    Searches the specified file_name for any DPAPI blobs, extracting
    the blob data and masterkey GUID for any found. For any carved blobs,
    a DpapiBlob protobuf is contructed and returned.
    """

    blob_limit = 1000

    await logger.adebug("Carving DPAPI blobs from a file", file_name=file_name)

    dpapi_blobs = await carve_dpapi_blobs_from_file_helper(file_name, nemesis_uuid)

    if len(dpapi_blobs) < blob_limit:
        # parse each blob out if there are less than 1000 instances
        #   this is so we avoid things like Chrome DBs/etc. (for now)

        dpapi_blob_ids: List[str] = []
        dpapi_blob_messages: List[pb.DpapiBlobMessage] = []

        for dpapi_blob in dpapi_blobs:
            try:
                dpapi_blob_message = pb.DpapiBlobMessage()
                dpapi_blob_message.metadata.CopyFrom(metadata)

                blob_pb = dpapi_blob_message.data.add()

                # create a new UUID for this blob so the file it originated from can track it
                dpapi_blob_id = f"{uuid.uuid4()}"
                dpapi_blob_ids.append(dpapi_blob_id)

                blob_pb.dpapi_blob_id = dpapi_blob_id
                blob_pb.originating_object_id = nemesis_uuid
                blob_pb.masterkey_guid = dpapi_blob.dpapi_master_key_guid
                blob_pb.is_decrypted = False

                blob_pb.enc_data_bytes = dpapi_blob.dpapi_data

                dpapi_blob_messages.append(dpapi_blob_message)

            except Exception as e:
                await logger.awarning(f"Error extracting dpapi blob: {e}")

        return (dpapi_blob_ids, dpapi_blob_messages)
    else:
        await logger.awarning(f"Number of DPAPI blobs in file '{file_name}' (nemesis_uuid {nemesis_uuid}) ({len(dpapi_blobs)}) exceeds the {blob_limit} limit")
        return None


async def carve_dpapi_blobs_from_reg_key(raw_bytes: bytes, originating_registry_id: str, metadata: pb.Metadata) -> Optional[tuple[list[str], list[pb.DpapiBlobMessage]]]:
    """Carves dpapi blobs from a binary blob.

    Searches the specified file_name for any DPAPI blobs, extracting
    the blob data and masterkey GUID for any found. For any carved blobs,
    a DpapiBlob protobuf is contructed and returned.
    """

    blob_limit = 1000

    await logger.adebug("Carving DPAPI blobs from a binary blob")

    dpapi_blobs = await carve_dpapi_blobs_from_bytes_helper(raw_bytes)

    if len(dpapi_blobs) < blob_limit:
        # parse each blob out if there are less than 1000 instances
        #   this is so we avoid things like Chrome DBs/etc. (for now)

        dpapi_blob_ids: List[str] = []
        dpapi_blob_messages: List[pb.DpapiBlobMessage] = []

        for dpapi_blob in dpapi_blobs:
            try:
                dpapi_blob_message = pb.DpapiBlobMessage()
                dpapi_blob_message.metadata.CopyFrom(metadata)

                blob_pb = dpapi_blob_message.data.add()

                # create a new UUID for this blob so the file it originated from can track it
                dpapi_blob_id = f"{uuid.uuid4()}"
                dpapi_blob_ids.append(dpapi_blob_id)

                blob_pb.dpapi_blob_id = dpapi_blob_id
                blob_pb.originating_registry_id = originating_registry_id
                blob_pb.masterkey_guid = dpapi_blob.dpapi_master_key_guid
                blob_pb.is_decrypted = False

                blob_pb.enc_data_bytes = dpapi_blob.dpapi_data

                dpapi_blob_messages.append(dpapi_blob_message)

            except Exception as e:
                await logger.awarning(f"Error extracting dpapi blob: {e}")

        return (dpapi_blob_ids, dpapi_blob_messages)
    else:
        await logger.awarning(f"Number of DPAPI blobs in blob (originating_registry_id {originating_registry_id}) ({len(dpapi_blobs)}) exceeds the {blob_limit} limit")
        return None


##################################################
#
# Misc helpers
#
##################################################


def extract_binary_path(raw_file_path: str) -> Optional[str]:
    """
    Adapted regex from Seatbelt/SharpUp that extracts out a binary path from
    a raw (potentially quoted) file path.
    """

    match = re.search(r"^\W*(([a-z]:\\|\\\\[a-zA-Z0-9\-\.]+|system).+?(\.exe|\.dll|\.sys))\W*", raw_file_path, re.IGNORECASE)

    if match:
        return match.groups()[0]
    else:
        return None


def get_py_files(src: str, only_file_modules: bool = False) -> List[str]:
    """Walks a directory to retrieve all .py files.

    Ref: https://stackoverflow.com/a/57892961
    """

    cwd = os.getcwd()
    py_files = []
    for root, dirs, files in os.walk(src):
        for file in files:
            if file.endswith(".py"):
                if only_file_modules:
                    # retrieve just the file modules we want to use
                    if (root == src) and (not file.startswith("__")) and (file != "Meta.py"):
                        py_files.append(os.path.split(file)[-1][:-3].lower())
                else:
                    py_files.append(os.path.join(cwd, root, file))
    return py_files


def dynamic_import(module_name: str, py_path: str):
    """Dynamically imports a Python module from a supplied path.

    TODO: unsure of the exact return type here

    Ref: https://stackoverflow.com/a/57892961
    """

    module_spec = importlib.util.spec_from_file_location(module_name, py_path)
    if module_spec is None:
        raise ImportError(f"module_spec is None for the supplied module_name '{module_name}' and py_path '{py_path}'")

    module = importlib.util.module_from_spec(module_spec)
    if module is None:
        raise ImportError(f"module is None for the supplied module_name '{module_name}' and py_path '{py_path}'")

    if module_spec.loader is None:
        raise ImportError(f"module_spec.loader is None for the supplied module_name '{module_name}' and py_path '{py_path}'")

    module_spec.loader.exec_module(module)

    return module


def dynamic_import_from_src(src: str, star_import: bool = True):
    """Enumerates all Python modules on a path and dynamically imports them.

    TODO: unsure of the exact return type here

    Ref: https://stackoverflow.com/a/57892961
    """
    sys.path.insert(0, os.getcwd() + f"/{src}")  # make sure our file folder is set for those imports
    my_py_files = get_py_files(src)
    file_modules = get_py_files(src, True)
    imported = dict()
    for py_file in my_py_files:
        module_name = os.path.split(py_file)[-1][:-3]
        imported_module = dynamic_import(module_name, py_file)
        if star_import:
            for obj in dir(imported_module):
                imported[obj.lower()] = imported_module.__dict__[obj]
        else:
            imported[module_name] = imported_module
    return (imported, file_modules)


def hash_file(nemesis_uuid: str) -> Optional[pb.FileHashes]:
    """Hashes a supplied file path.

    Reads the given nemesis UUID file from disk in 128k byte chunks
    and hashes the file bytes, returning md5/sha1/sha256 digests of
    the input data.
    """

    chunk_size = 128000
    file_hashes = pb.FileHashes()

    try:
        with open(nemesis_uuid, "rb") as f:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()

            while chunk := f.read(chunk_size):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

            file_hashes.md5 = md5.hexdigest()
            file_hashes.sha1 = sha1.hexdigest()
            file_hashes.sha256 = sha256.hexdigest()

            return file_hashes

    except Exception as e:
        logger.exception(e, message="Exception while hashing file", file_uuid=nemesis_uuid)
        return None


def get_magic_type(nemesis_uuid: str, mime: bool = False) -> str:
    """Gets the magic type of a file.

    Uses python-magic to retrieve the file type via libmagic for the
    specified nemesis UUID file (a la the 'file' command but without subprocess).
    """

    magic_string = magic.from_file(nemesis_uuid, mime=mime)

    if magic_string.startswith("Composite Document File V2 Document"):
        magic_string = "Composite Document File V2 Document"

    return magic_string


def is_dotnet_assembly(nemesis_uuid: str) -> bool:
    """Returns True if the supplied file name is a .NET assembly."""
    # a bit of a hack but ended up being more reliable than the yara rule
    return re.match(".*\\.Net assembly.*", get_magic_type(nemesis_uuid), re.IGNORECASE) is not None


def tika_compatible(mime_type: str) -> bool:
    """Returns True if the mime type can be used with Tika."""

    # from https://tika.apache.org/2.8.0/formats.html#Full_list_of_Supported_Formats_in_standard_artifacts
    supported_mime_types = {
        "text/csv": 1,
        "text/plain": 1,
        "text/html": 1,
        "application/vnd.wap.xhtml+xml": 1,
        "application/x-asp": 1,
        "application/xhtml+xml": 1,
        "image/png": 1,
        "image/vnd.wap.wbmp": 1,
        "image/x-jbig2": 1,
        "image/bmp": 1,
        "image/x-xcf": 1,
        "image/gif": 1,
        "image/x-ms-bmp": 1,
        "image/jpeg": 1,
        # "application/mbox": 1,
        "image/emf": 1,
        # "application/x-msaccess": 1,
        "application/x-tika-msoffice-embedded; format=ole10_native": 1,
        "application/msword": 1,
        "application/vnd.visio": 1,
        "application/x-tika-ole-drm-encrypted": 1,
        "application/vnd.ms-project": 1,
        "application/x-tika-msworks-spreadsheet": 1,
        "application/x-mspublisher": 1,
        "application/vnd.ms-powerpoint": 1,
        "application/x-tika-msoffice": 1,
        "application/sldworks": 1,
        "application/x-tika-ooxml-protected": 1,
        "application/vnd.ms-excel": 1,
        # "application/vnd.ms-outlook": 1,
        "application/vnd.ms-excel.workspace.3": 1,
        "application/vnd.ms-excel.workspace.4": 1,
        "application/vnd.ms-excel.sheet.2": 1,
        "application/vnd.ms-excel.sheet.3": 1,
        "application/vnd.ms-excel.sheet.4": 1,
        "image/wmf": 1,
        "application/vnd.ms-htmlhelp": 1,
        "application/x-chm": 1,
        "application/chm": 1,
        "application/onenote; format=one": 1,
        "application/vnd.ms-powerpoint.template.macroenabled.12": 1,
        "application/vnd.ms-excel.addin.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template": 1,
        "application/vnd.ms-excel.sheet.binary.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": 1,
        "application/vnd.ms-powerpoint.slide.macroenabled.12": 1,
        "application/vnd.ms-visio.drawing": 1,
        "application/vnd.ms-powerpoint.slideshow.macroenabled.12": 1,
        "application/vnd.ms-powerpoint.presentation.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.slide": 1,
        "application/vnd.ms-excel.sheet.macroenabled.12": 1,
        "application/vnd.ms-word.template.macroenabled.12": 1,
        "application/vnd.ms-word.document.macroenabled.12": 1,
        "application/vnd.ms-powerpoint.addin.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template": 1,
        "application/vnd.ms-xpsdocument": 1,
        "application/vnd.ms-visio.drawing.macroenabled.12": 1,
        "application/vnd.ms-visio.template.macroenabled.12": 1,
        "model/vnd.dwfx+xps": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.template": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": 1,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": 1,
        "application/vnd.ms-visio.stencil": 1,
        "application/vnd.ms-visio.template": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow": 1,
        "application/vnd.ms-visio.stencil.macroenabled.12": 1,
        "application/vnd.ms-excel.template.macroenabled.12": 1,
        "application/vnd.ms-word2006ml": 1,
        "application/vnd.ms-outlook-pst": 1,
        "application/rtf": 1,
        "application/vnd.ms-wordml": 1,
        "image/ocr-x-portable-pixmap": 1,
        "image/ocr-jpx": 1,
        "image/x-portable-pixmap": 1,
        "image/ocr-jpeg": 1,
        "image/ocr-jp2": 1,
        "image/jpx": 1,
        "image/ocr-png": 1,
        "image/ocr-tiff": 1,
        "image/ocr-gif": 1,
        "image/ocr-bmp": 1,
        "image/jp2": 1,
        "application/pdf": 1,
        "application/vnd.wordperfect; version=5.1": 1,
        "application/vnd.wordperfect; version=5.0": 1,
        "application/vnd.wordperfect; version=6.x": 1,
        "application/xml": 1,
    }

    if mime_type in supported_mime_types:
        return True
    else:
        return False


def is_office_doc(file_path: str) -> bool:
    """Returns True if the file has an extension that indicates it's an Office document."""
    office_regex = "^.*\\.(doc|docx|docm|ppt|pptx|xls|xlsx|odt|ods|odp|ppt|pptx)$"
    return re.match(office_regex, file_path, re.IGNORECASE) is not None


def can_convert_to_pdf(file_path: str) -> bool:
    """Returns True if the supplied file_path matches an extension that Gotenberg can convert."""
    path_regex = (
        "^.*\\.(bib|doc|docx|fodt|html|ltx|txt|odt|ott|pdb|psw|odg|"
        "rtf|sdw|stw|sxw|uot|vor|wps|epub|emf|eps|fodg|met|odd|otg|dotx|"
        "pbm|pct|pgm|ppm|ras|std|svg|svm|swf|sxd|sxw|tiff|xhtml|xpm|xltx|"
        "fodp|potm|pot|pptx|pps|ppt|pwp|sda|sdd|sti|sxi|uop|wmf|dbf|"
        "dif|fods|ods|ots|pxl|sdc|slk|stc|sxc|uos|xls|xlt|xlsx|odp)$"
    )
    return re.match(path_regex, file_path, re.IGNORECASE) is not None


def is_pe_extension(file_path: str) -> bool:
    """Returns True if the supplied file_path matches a number of PE file extensions."""
    pe_regex = "^.*\\.(acm|ax|cpl|dll|drv|efi|exe|mui|ocx|scr|sys|tsp)$"
    return re.match(pe_regex, file_path, re.IGNORECASE) is not None


def is_source_code(file_path: str) -> bool:
    """Returns True if the supplied file_path matches a number of supported source code file extensions."""
    source_code_regex = "^.*\\.(aspx|c|cpp|cs|go|groovy|java|jsp|js|lua|php|php3|php4|php5|ps1|psd1|psm1|py|rb|rs|sql|sh|swift|vb|vbs)$"
    return re.match(source_code_regex, file_path, re.IGNORECASE) is not None


def map_extension_to_language(extension: str) -> str:
    """Maps a file extension to a source code language."""
    language_mappings = {
        "aspx": "ASPNET",
        "c": "C",
        "cpp": "CPLusPlus",
        "cs": "CSharp",
        "go": "Golang",
        "groovy": "Groovy",
        "java": "Java",
        "jsp": "JavaServerPages",
        "lua": "Lua",
        "php": "PHP",
        "php3": "PHP",
        "php4": "PHP",
        "php5": "PHP",
        "ps1": "PowerShell",
        "psd1": "PowerShell",
        "psm1": "PowerShell",
        "py": "Python",
        "rb": "Ruby",
        "rs": "Rust",
        "sql": "SQL",
        "sh": "BashScript",
        "swift": "Swift",
        "vb": "VisualBasic",
        "vbs": "VisualBasicScript",
    }
    return language_mappings.get(extension.lower(), "unknown")


def scan_with_yara(file_path: str, rule_name: str) -> bool:
    """Scans a supplied file path with the given Yara rule.

    Returns the True/False value of the rule match.
    """
    rule = yara.compile(filepath=f"./enrichment/lib/file_parsers/yara/{rule_name}.yara")
    return len(rule.match(file_path)) != 0


def nemesis_parsed_data_error(message: str) -> pb.ParsedData:
    """Returns a `ParsedData` protobuf with the given error message."""
    parsed_data = pb.ParsedData()
    parsed_data.error = message
    return parsed_data


def nemesis_error(message: str) -> pb.Error:
    """Returns a general Nemesis `error` protobuf message"""
    error = pb.Error()
    error.error = message
    return error


def is_jar(path: str) -> bool:
    """Returns true if the file is a JAR."""
    magic = get_magic_type(path).lower()
    is_jar_file = True if magic == "java archive data (jar)" else False
    is_zip_file = libarchive.is_archive(path, ["zip"])
    return is_jar_file and is_zip_file


def is_archive(path: str) -> bool:
    """Returns true if the file supplied is a Zip, 7z, Tarball, or CAB."""
    return is_jar(path) or zipfile.is_zipfile(path) or py7zr.is_7zfile(path) or tarfile.is_tarfile(path) or libarchive.is_archive(path, ["cab"])


def get_archive_size(path: str) -> int:
    """Iterates over a zip's info entries and returns the total size.

    NOTE: not 100% reliable against malicious inputs! (i.e., we can still get zip-bombed)

    TODO: how to handle logging here?
    """
    if zipfile.is_zipfile(path):
        f = zipfile.ZipFile(path)
        return sum([zinfo.file_size for zinfo in f.filelist])
    elif py7zr.is_7zfile(path):
        f = py7zr.SevenZipFile(path)
        return f.archiveinfo().uncompressed
    elif tarfile.is_tarfile(path):
        return estimate_uncompressed_gz_size(path)
    elif libarchive.is_archive(path, ["cab"]):
        total_size = 0
        with libarchive.Archive(path) as a:
            for entry in a:
                total_size += entry.size
        return total_size
    # special case for JARs
    elif libarchive.is_archive(path, ["zip"]):
        total_size = 0
        with libarchive.Archive(path) as a:
            for entry in a:
                total_size += entry.size
        return total_size
    else:
        # File is not a supported archive format
        return -1


def estimate_uncompressed_gz_size(filename) -> int:
    """Estimates a gzip uncompressed size.

    Directly from https://stackoverflow.com/a/68939759
    """

    try:
        # From the input file, get some data:
        # - the 32 LSB from the gzip stream
        # - 1MB sample of compressed data
        # - compressed file size
        with open(filename, "rb") as gz_in:
            sample = gz_in.read(1000000)
            gz_in.seek(-4, SEEK_END)
            lsb = struct.unpack("I", gz_in.read(4))[0]
            file_size = os.fstat(gz_in.fileno()).st_size

        # Estimate the total size by decompressing the sample to get the
        # compression ratio so we can extrapolate the uncompressed size
        # using the compression ratio and the real file size
        dobj = zlib.decompressobj(31)
        d_sample = dobj.decompress(sample)

        compressed_len = len(sample) - len(dobj.unconsumed_tail)
        decompressed_len = len(d_sample)

        estimate = int(file_size * decompressed_len / compressed_len)

        # 32 LSB to zero
        mask = ~0xFFFFFFFF

        # Kill the 32 LSB to be substituted by the data read from the file
        adjusted_estimate = (estimate & mask) | lsb

        return adjusted_estimate

    except Exception as e:
        logger.warning(f"Error in estimate_uncompressed_gz_size: {e}")
        return -1


class FileNotSupportedException(Exception):
    """Raised when a file is not supported"""

    pass


def extract_archive(path: str) -> str:
    """
    Extracts an archive file to a temporary directory and returns the
    temporary directory name
    """

    # unpack the zip to a temporary directory
    tmp_dir = f"/tmp/{uuid.uuid4()}"

    if zipfile.is_zipfile(path):
        shutil.unpack_archive(path, tmp_dir, "zip")
    elif py7zr.is_7zfile(path):
        shutil.register_unpack_format("7zip", [".7z"], py7zr.unpack_7zarchive)
        shutil.unpack_archive(path, tmp_dir, "7zip")
    elif tarfile.is_tarfile(path):
        shutil.unpack_archive(path, tmp_dir, "tar")
    elif libarchive.is_archive(path, ["cab"]):
        with libarchive.Archive(path) as a:
            for entry in a:
                target_path = f"{tmp_dir}/{entry.pathname}"
                # make sure we create all the subfolders needed to extract this file entry
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "wb") as f:
                    f.write(a.read(entry.size))
    # special case for JARs
    elif libarchive.is_archive(path, ["zip"]):
        with libarchive.Archive(path) as a:
            for entry in a:
                target_path = f"{tmp_dir}/{entry.pathname}"
                # make sure we create all the subfolders needed to extract this file entry
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "wb") as f:
                    f.write(a.read(entry.size))
    else:
        raise FileNotSupportedException("File is not a supported archive format")
    return tmp_dir


def run_noseyparker(path: str) -> Optional[pb.NoseyParker]:
    """Runs NoseyParker on the specified file/folder path.

    Runs NoseyParker on the specified file/folder path, returning a
    pb.NoseyParker protobuf object representing the results if successful.

    The NoseyParker binary is built in the NoseyParker build container and copied to
    /opt/noseyparker/noseyparker when this container is built.

    """

    # the temporary datastore to use for NoseyParker
    temp_dir = f"/tmp/{uuid.uuid4()}/"

    if not os.path.exists("/opt/noseyparker-rules/"):
        os.makedirs("/opt/noseyparker-rules/")

    # run a scan with the temporary datastore
    result = subprocess.run(
        [
            "/opt/noseyparker/noseyparker",
            "scan",
            "--datastore",
            temp_dir,
            "--rules",
            "/opt/noseyparker-rules/",
            path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # get the result from stdout as a JSON blob
    result = subprocess.run(
        ["/opt/noseyparker/noseyparker", "report", "--datastore", temp_dir, "--format=json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    np_json_output_str = result.stdout.decode("utf-8")

    # clean up the temporary datastore
    if os.path.exists(temp_dir) and os.path.isdir(temp_dir):
        shutil.rmtree(temp_dir)

    # this will throw if the output is not proper Json
    np_json_output = json.loads(np_json_output_str)

    if not np_json_output:
        logger.debug("No results from NoseyParker scan")
        return None

    # have to add this to ensure it's a dict instead of a list
    np_dict = {"rule_matches": np_json_output}

    # TODO: emit hash instances specifically to the queue?

    # try to parse the dict/json output directly to the corresponding protobuf instance
    pb_np = ParseDict(np_dict, pb.NoseyParker())
    return pb_np


def run_noseyparker_on_archive(path: str) -> Optional[pb.NoseyParker]:
    """Runs NoseyParker on an archive.

    Extracts an archive file to a temporary directory, runs NoseyParker on it,
    removes the temp directory, and returns the NoseyParker results.

    """

    try:
        # extract the archive
        tmp_dir = extract_archive(path)

        if tmp_dir:
            # run NoseyParker on the extracted results
            pb_np = run_noseyparker(tmp_dir)

            # cleanup the temporary directory
            if tmp_dir and os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)

            return pb_np

    except Exception as e:
        logger.exception(e, message="Exception run_noseyparker_on_archive", path=path)
        return None


def get_username_from_slack_file_path(file_path: str) -> str:
    """
    Checks if a file path is a Slack file (slack-downloads, slack-workspaces)
    and returns a string of the username extracted from the path.
    """

    regex1 = re.compile(".*/(?P<username>.*)/AppData/Roaming/Slack/storage/(slack-downloads|slack-workspaces)$")
    matches = regex1.search(file_path, re.IGNORECASE)

    if matches:
        return matches.group("username").lower()
    else:
        return ""
