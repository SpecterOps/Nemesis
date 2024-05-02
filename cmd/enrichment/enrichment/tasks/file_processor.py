# Standard Libraries
import asyncio
import glob
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime
from typing import Optional

# 3rd Party Libraries
import aiohttp
import enrichment.lib.canaries as canary_helpers
import enrichment.lib.helpers as helpers
import nemesiscommon.constants as constants
import nemesispb.nemesis_pb2 as pb
import plyara
import structlog
import yara
from anyascii import anyascii
from binaryornot.check import is_binary
from enrichment.lib.nemesis_db import NemesisDb
from enrichment.services.text_extractor import TextExtractorInterface
from nemesiscommon.messaging import (MessageQueueConsumerInterface,
                                     MessageQueueProducerInterface)
from nemesiscommon.nemesis_tempfile import TempFile
from nemesiscommon.services.alerter import AlerterInterface
from nemesiscommon.storage import StorageInterface
from nemesiscommon.tasking import TaskInterface
from plyara import utils as plyara_utils
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger(module=__name__)


class FileProcessor(TaskInterface):
    alerter: AlerterInterface
    storage: StorageInterface
    db: NemesisDb
    text_extractor: TextExtractorInterface

    # URIs
    crack_list_uri: str
    dotnet_uri: str
    gotenberg_uri: str
    kibana_url: str

    # Queues
    in_q_filedata: MessageQueueConsumerInterface
    in_q_filedataenriched: MessageQueueConsumerInterface
    out_q_authdata: MessageQueueProducerInterface
    out_q_chromiumcookies: MessageQueueProducerInterface
    out_q_chromiumdownloads: MessageQueueProducerInterface
    out_q_chromiumhistory: MessageQueueProducerInterface
    out_q_chromiumlogins: MessageQueueProducerInterface
    out_q_chromiumstatefile: MessageQueueProducerInterface
    out_q_dpapiblob: MessageQueueProducerInterface
    out_q_dpapimasterkey: MessageQueueProducerInterface
    out_q_filedata: MessageQueueProducerInterface
    out_q_filedataenriched: MessageQueueProducerInterface
    out_q_filedataplaintext: MessageQueueProducerInterface
    out_q_filedatasourcecode: MessageQueueProducerInterface
    out_q_rawdata: MessageQueueProducerInterface

    chunk_size: int
    extracted_archive_size_limit: int
    plaintext_size_limit: int
    data_download_dir: str
    kibana_url: str

    def __init__(
        self,
        alerter: AlerterInterface,
        storage: StorageInterface,
        db: NemesisDb,
        text_extractor: TextExtractorInterface,
        # URIs
        crack_list_uri: str,
        dotnet_uri: str,
        gotenberg_uri: str,
        public_kibana_url: str,
        # Other settings
        chunk_size: int,
        data_download_dir: str,
        extracted_archive_size_limit: str,
        plaintext_size_limit: str,
        # Queues
        in_q_filedata: MessageQueueConsumerInterface,
        in_q_filedataenriched: MessageQueueConsumerInterface,
        out_q_alerting: MessageQueueProducerInterface,
        out_q_authdata: MessageQueueProducerInterface,
        out_q_chromiumcookies: MessageQueueProducerInterface,
        out_q_chromiumdownloads: MessageQueueProducerInterface,
        out_q_chromiumhistory: MessageQueueProducerInterface,
        out_q_chromiumlogins: MessageQueueProducerInterface,
        out_q_chromiumstatefile: MessageQueueProducerInterface,
        out_q_dpapiblob: MessageQueueProducerInterface,
        out_q_dpapimasterkey: MessageQueueProducerInterface,
        out_q_filedata: MessageQueueProducerInterface,
        out_q_filedataenriched: MessageQueueProducerInterface,
        out_q_filedataplaintext: MessageQueueProducerInterface,
        out_q_filedatasourcecode: MessageQueueProducerInterface,
        out_q_rawdata: MessageQueueProducerInterface,
    ):
        self.alerter = alerter
        self.storage = storage
        self.db = db
        self.text_extractor = text_extractor

        self.crack_list_uri = crack_list_uri
        self.dotnet_uri = dotnet_uri
        self.gotenberg_uri = gotenberg_uri
        self.kibana_url = public_kibana_url

        self.in_q_filedata = in_q_filedata
        self.in_q_filedataenriched = in_q_filedataenriched
        self.out_q_alert = out_q_alerting
        self.out_q_authdata = out_q_authdata
        self.out_q_chromiumcookies = out_q_chromiumcookies
        self.out_q_chromiumdownloads = out_q_chromiumdownloads
        self.out_q_chromiumhistory = out_q_chromiumhistory
        self.out_q_chromiumlogins = out_q_chromiumlogins
        self.out_q_chromiumstatefile = out_q_chromiumstatefile
        self.out_q_dpapiblob = out_q_dpapiblob
        self.out_q_dpapimasterkey = out_q_dpapimasterkey
        self.out_q_filedata = out_q_filedata
        self.out_q_filedataenriched = out_q_filedataenriched
        self.out_q_filedataplaintext = out_q_filedataplaintext
        self.out_q_filedatasourcecode = out_q_filedatasourcecode
        self.out_q_rawdata = out_q_rawdata

        # number of bytes to read at a time per file
        self.chunk_size = chunk_size
        # folder to download temp files to
        self.data_download_dir = data_download_dir
        # upper size limit of an (extracted) archive to process, in MB
        self.extracted_archive_size_limit = int(extracted_archive_size_limit) * 1000000
        # upper size limit of a extracted text to process, in MB
        self.plaintext_size_limit = int(plaintext_size_limit) * 1000000

        # load up the file parsing modules
        (self.file_modules, self.file_module_names) = helpers.dynamic_import_from_src("./enrichment/lib/file_parsers")

        # load up Yara rules
        yara_file_paths = {f"{ind}": elem for ind, elem in enumerate(glob.glob("./enrichment/lib/public_yara/**/*.yar*", recursive=True))}
        self.yara_rules = yara.compile(filepaths=yara_file_paths)

        # save off the rule definitions in a readable way so the rule text
        #   can be passed along with a rule hit
        self.yara_rule_definitions = {}
        yara_rule_definitions_raw = list()
        parser = plyara.Plyara()
        for file_path in yara_file_paths.values():
            with open(file_path, 'r') as fh:
                try:
                    parsed_yara_rules = parser.parse_string(fh.read())
                    yara_rule_definitions_raw += parsed_yara_rules
                except Exception as e:
                    logger.error(f"Error parsing yara file '{file_path}' : {e}")
            parser.clear()
        pass
        for rule_def in yara_rule_definitions_raw:
            self.yara_rule_definitions[rule_def['rule_name']] = plyara_utils.rebuild_yara_rule(rule_def)

    async def run(self) -> None:
        await logger.ainfo("Starting the File Processor")

        results = await asyncio.gather(
            self.in_q_filedata.Read(self.handle_file_data),  # type: ignore
            self.in_q_filedataenriched.Read(self.handle_file_data_enriched),  # type: ignore
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, Exception):
                await logger.aexception(result, message="Error in File Processor")

        await asyncio.Future()

    async def handle_file_data(self, q_msg: pb.FileDataIngestionMessage) -> None:
        structlog.contextvars.clear_contextvars()
        await self.process_file_data(q_msg)

    async def handle_file_data_enriched(self, q_msg: pb.FileDataEnrichedMessage) -> None:
        structlog.contextvars.clear_contextvars()
        await self.process_file_data_enriched(q_msg)

    @aio.time(Summary("process_file", "Time spent processing a file"))  # type: ignore
    async def process_file(
        self,
        nemesis_uuid: str,
        originating_object_id: str,
        file_path: str,
        metadata: pb.Metadata,
        scan_unknown: bool = False,
    ) -> pb.FileDataEnriched:
        """Main file_data processing function.

        This is where all the main file enrichment logic resides.
        """
        ###########################################################
        #
        # Basic/universal file processing
        #
        ###########################################################

        with await self.storage.download(uuid.UUID(nemesis_uuid)) as file:
            return await self.process_enrichments(nemesis_uuid, originating_object_id, file.name, file_path, metadata, scan_unknown)

    async def process_enrichments(
        self,
        file_uuid_str: str,
        originating_object_id: str,
        file_path_on_disk: str,
        file_path: str,
        metadata: pb.Metadata,
        scan_unknown: bool,
    ) -> pb.FileDataEnriched:
        """Main function for various base file enrichments."""

        file_data = pb.FileDataEnriched()

        # track which enrichments ran/failed
        enrichments_success = []
        enrichments_failure = []

        # whether to skip the DPAPI blob carving for specific files
        skip_dpapi_carve = False

        # double check/ensure the path is forward slash normalized
        file_path = file_path.replace("\\", "/")

        # get the base file name
        file_name = os.path.basename(file_path)

        # hash the file bytes, getting a file_hashes protobuf back
        file_hashes = helpers.hash_file(file_path_on_disk)
        if file_hashes:
            enrichments_success.append(constants.E_FILE_HASHES)
            file_data.hashes.CopyFrom(file_hashes)
        else:
            enrichments_failure.append(constants.E_FILE_HASHES)
            await logger.aerror(f"Hash enrichment: Failed to hash file: {file_path_on_disk}")

        # now get its magic type from the first 2048 bytes using python-magic
        file_magic_type = helpers.get_magic_type(file_path_on_disk)

        # check if this file is an office document
        is_office_doc = helpers.is_office_doc(file_path)

        # check if this file is a supported type of source code
        is_source_code = helpers.is_source_code(file_path)

        # check if the file extension indicates that Gotenberg can convert the document to a pdf
        can_convert_to_pdf = helpers.can_convert_to_pdf(file_path)

        # true if the file is binary, false if it's text (e.g., source code)
        file_is_binary = is_binary(file_path_on_disk)

        file_data.object_id = file_uuid_str
        file_data.originating_object_id = originating_object_id
        file_data.name = file_name
        file_data.size = os.path.getsize(file_path_on_disk)
        file_data.path = file_path
        file_data.extension = pathlib.Path(file_path).suffix.strip(".")
        file_data.magic_type = file_magic_type
        file_data.is_binary = file_is_binary
        file_data.is_office_doc = is_office_doc
        file_data.is_source_code = is_source_code
        file_data.nemesis_file_type = "unknown"

        try:
            file_previously_processed = (await self.db.is_file_processed(file_data.hashes.sha256))[0][0]
        except:
            file_previously_processed = False

        if file_previously_processed:
            await logger.ainfo(
                "File has already been processed.",
                file_name=file_data.name,
                sha256=file_data.hashes.sha256,
            )

        ###########################################################
        #
        # Nemesis-defined file format parsing
        #
        ###########################################################

        possible_nemesis_file_types = []

        # TODO: redo this flow so modules are instantiated only once

        # first iterate through every file module to see if we have a path match
        for file_module_name in self.file_module_names:
            try:
                file_module = self.file_modules[file_module_name](file_path_on_disk, file_data, metadata)
            except Exception as e:
                await logger.aexception(e, message="exception (likely mismatching class/file name)")
                continue

            try:
                if file_module.check_path():
                    # TODO: save module instead of name possibly?
                    possible_nemesis_file_types.append(file_module_name)
            except Exception as e:
                await logger.aexception(
                    e,
                    message="Exception in running check_path() for module",
                    file_module_name=file_module_name,
                )

        await logger.adebug(f"possible_nemesis_file_types: {possible_nemesis_file_types}")

        # then verify the file contents for any potential matches
        if len(possible_nemesis_file_types) > 0:
            for possible_nemesis_file_type in possible_nemesis_file_types:
                try:
                    file_module = self.file_modules[possible_nemesis_file_type](file_path_on_disk, file_data, metadata)
                except Exception as e:
                    await logger.aexception(
                        e,
                        message="Exception (likely mismatching class/file name)",
                    )
                    continue
                try:
                    if file_module.check_content():
                        # if the content matches then break and mark this file as identified
                        file_data.nemesis_file_type = possible_nemesis_file_type
                        break
                except Exception as e:
                    await logger.aexception(
                        e,
                        message="Exception in running check_content()",
                        possible_file_type=possible_nemesis_file_type,
                    )
        else:
            # if there's no type match AND we're scanning unknown filetypes
            if scan_unknown:
                # first iterate through every file module to see if we have a path match
                for file_module_name in self.file_module_names:
                    try:
                        file_module = self.file_modules[file_module_name](file_path_on_disk, file_data, metadata)
                    except Exception as e:
                        await logger.aexception(
                            e,
                            message="Exception (likely mismatching class/file name)",
                        )
                        continue

                    try:
                        if file_module.check_content():
                            # if the content matches then break and mark this file as identified
                            file_data.nemesis_file_type = file_module_name
                            break
                    except Exception as e:
                        await logger.aexception(e, message="Exception in running check_content()")

        await logger.adebug("file_data.nemesis_file_type", file_type=file_data.nemesis_file_type)

        # if we don't have an unknown file type, parse the content using the matching module
        if file_data.nemesis_file_type != "unknown":
            file_module = self.file_modules[file_data.nemesis_file_type](file_path_on_disk, file_data, metadata)

            auth_data_msg: pb.AuthenticationDataIngestionMessage
            (parsed, auth_data_msg) = file_module.parse()

            if len(auth_data_msg.data) > 0:
                # if we have plaintext auth data, emit that to the auth_data_q_out queue
                await self.out_q_authdata.Send(auth_data_msg.SerializeToString())
                await logger.ainfo(
                    "Authentication data found!",
                    count=len(auth_data_msg.data),
                    types=[d.type for d in auth_data_msg.data],
                )

            if parsed and parsed is not None:
                enrichments_success.append(constants.E_KNOWN_FILE_PARSED)
                try:
                    file_data.parsed_data.CopyFrom(parsed)
                    try:
                        if file_data.parsed_data.has_parsed_credentials:
                            if not file_previously_processed:
                                await self.alerter.file_data_alert(
                                    file_data=file_data,
                                    metadata=metadata,
                                    title="Parsed Credentials",
                                    text="File is a known type and has some form of parsed credentials!",
                                )
                    except:
                        pass

                except Exception as e:
                    await logger.aexception(
                        e,
                        message="Exception parsing data with module",
                        file_module=file_module,
                    )
                    err = helpers.nemesis_parsed_data_error(f"Exception parsing data with module '{file_module}' : {e}")
                    file_data.parsed_data.CopyFrom(err)

        ###########################################################
        #
        # Special post-processing of specific file types
        #
        ###########################################################

        if file_data.parsed_data.WhichOneof("data_type") == "dpapi_masterkey":
            # if the parsed data is a DPAPI masterkey, publish it to the queue
            skip_dpapi_carve = True
            dpapi_masterkey_message = pb.DpapiMasterkeyMessage()
            dpapi_masterkey_message.metadata.CopyFrom(metadata)
            dpapi_masterkey_message.data.append(file_data.parsed_data.dpapi_masterkey)
            await logger.ainfo("Detected DPAPI masterkey, emitting DpapiMasterkeyMessage")
            await self.out_q_dpapimasterkey.Send(dpapi_masterkey_message.SerializeToString())

        elif file_data.parsed_data.WhichOneof("data_type") == "chromium_history":
            skip_dpapi_carve = True
            await logger.ainfo("Detected Chromium history file, processing")
            await helpers.process_chromium_history(
                file_data.object_id,
                file_path_on_disk,
                metadata,
                file_data.parsed_data,
                self.out_q_chromiumhistory,
                self.out_q_chromiumdownloads,
            )

        elif file_data.parsed_data.WhichOneof("data_type") == "chromium_logins":
            skip_dpapi_carve = True
            await logger.ainfo("Detected Chromium logins file, processing")
            await helpers.process_chromium_logins(
                file_data.object_id, file_path_on_disk, metadata, file_data.parsed_data, self.out_q_chromiumlogins
            )

        elif file_data.parsed_data.WhichOneof("data_type") == "chromium_cookies":
            skip_dpapi_carve = True
            await logger.ainfo("Detected Chromium cookies file, processing")
            await helpers.process_chromium_cookies(
                file_data.object_id, file_path_on_disk, metadata, file_data.parsed_data, self.out_q_chromiumcookies
            )

        elif file_data.parsed_data.WhichOneof("data_type") == "chromium_state_file":
            skip_dpapi_carve = True
            chromium_state_file_message = pb.ChromiumStateFileMessage()
            chromium_state_file_message.metadata.CopyFrom(metadata)
            chromium_state_file_message.data.append(file_data.parsed_data.chromium_state_file)
            await logger.ainfo("Detected Chromium state file, emitting ChromiumStateFileMessage")
            await self.out_q_chromiumstatefile.Send(chromium_state_file_message.SerializeToString())

        # we have a likely JSON Chromium cookie dump
        elif file_data.magic_type == "JSON data" and (await helpers.is_chromium_cookie_json(file_path_on_disk)):
            await logger.ainfo("Detected Chromium cookies JSON file, processing")
            await helpers.process_cookies_json(
                file_data.object_id, file_path_on_disk, metadata, file_data.parsed_data, self.out_q_chromiumcookies
            )

        # if this file is Seatbelt data, emit a raw_data message so the data is properly processed
        elif file_data.magic_type == "JSON data" and helpers.scan_with_yara(file_path_on_disk, "seatbelt_json"):
            skip_dpapi_carve = True
            seatbelt_raw_data_message = pb.RawDataIngestionMessage()
            seatbelt_raw_data_message.metadata.CopyFrom(metadata)
            raw_data_message = seatbelt_raw_data_message.data.add()
            raw_data_message.data = file_data.object_id
            raw_data_message.tags.append("seatbelt_json")
            raw_data_message.is_file = True
            await logger.ainfo("Detected Seatbelt json file, emitting RawDataIngestionMessage")
            await self.out_q_rawdata.Send(seatbelt_raw_data_message.SerializeToString())

        # if this file is DPAPI domain backup key data, emit a raw_data message so the data is properly processed
        elif file_data.magic_type == "JSON data" and helpers.scan_with_yara(file_path_on_disk, "dpapi_domain_backupkey"):
            dpapi_raw_data_message = pb.RawDataIngestionMessage()
            dpapi_raw_data_message.metadata.CopyFrom(metadata)
            raw_data_message = dpapi_raw_data_message.data.add()
            raw_data_message.data = file_data.object_id
            raw_data_message.tags.append("dpapi_domain_backupkey")
            raw_data_message.is_file = True
            await logger.ainfo("Detected DPAPI domain backup key json file, emitting RawDataIngestionMessage")
            await self.out_q_rawdata.Send(dpapi_raw_data_message.SerializeToString())

        # if we have a registry file, try to extract all the strings and run NoseyParker on everything
        if file_data.magic_type.startswith("MS Windows registry file"):

            # skip DPAPI carving for registry hives since we do it manually
            skip_dpapi_carve = True

            with tempfile.NamedTemporaryFile(mode="a+") as temp_file:
                # first ascii
                subprocess.run(["strings", file_path_on_disk], stdout=temp_file, stderr=subprocess.PIPE)
                # now unicode
                subprocess.run(["strings", "--encoding=l", file_path_on_disk], stdout=temp_file, stderr=subprocess.PIPE)
                temp_file.seek(0)

                try:
                    noseyparker_output = helpers.run_noseyparker(temp_file.name)
                    enrichments_success.append(constants.E_NOSEYPARKER_SCAN)

                    if noseyparker_output and len(noseyparker_output.rule_matches) > 0:
                        file_data.noseyparker.CopyFrom(noseyparker_output)
                        if not file_previously_processed:
                            await self.alerter.file_data_alert(
                                file_data=file_data,
                                title="NoseyParker Results",
                                metadata=metadata,
                            )
                except Exception as e:
                    await logger.aexception(e, message="Noseyparker scanning failed")
                    enrichments_failure.append(constants.E_NOSEYPARKER_SCAN)

        ###########################################################
        #
        # DPAPI blob carving and processing
        #
        ###########################################################

        try:
            # Scan for the presence of DPAPI blobs using Yara
            if not skip_dpapi_carve and helpers.scan_with_yara(file_path_on_disk, "dpapi_blob"):
                enrichments_success.append(constants.E_DPAPI_BLOB_SCAN)

                file_data.contains_dpapi = True

                if not file_previously_processed:
                    await self.alerter.file_data_alert(
                        file_data=file_data,
                        metadata=metadata,
                        title="DPAPI data present",
                    )

                # carve any DPAPI blobs
                carved = await helpers.carve_dpapi_blobs_from_file(file_path_on_disk, file_uuid_str, metadata)

                if carved is not None:
                    (dpapi_blob_ids, dpapi_blob_messages) = carved
                    enrichments_success.append(constants.E_DPAPI_BLOB_CARVED)

                    # publish any carved DPAPI blobs to the queue
                    for dpapi_blob_message in dpapi_blob_messages:
                        await self.out_q_dpapiblob.Send(dpapi_blob_message.SerializeToString())

                    # If blobs were extracted, add those blobs to this file object
                    #   This is so blobs can be tracked from blob(s)->file and file->blob(s)
                    if dpapi_blob_ids and len(dpapi_blob_ids) > 0:
                        file_data.dpapi_blobs.extend(dpapi_blob_ids)
                else:
                    # "None" is returned on failure
                    enrichments_failure.append(constants.E_DPAPI_BLOB_CARVED)
        except Exception as e:
            await logger.aexception(
                e,
                message="Error when using helpers.scan_with_yara or helpers.carve_dpapi_blobs",
            )
            enrichments_failure.append(constants.E_DPAPI_BLOB_SCAN)

        ###########################################################
        #
        # Office document related processing
        #
        ###########################################################

        # Check if the office document was encrypted
        doc_is_encrypted = file_data.parsed_data.is_encrypted

        if file_data.size > self.plaintext_size_limit:
            # if a file is too large, make sure we don't use Gotenberg/Tika to prevent system freezes
            mime_type = "application/octet-stream"
            tika_compatible = False
            can_convert_to_pdf = False
        else:
            mime_type = await self.text_extractor.detect(file_path_on_disk)
            tika_compatible = helpers.tika_compatible(mime_type)

        await logger.ainfo(f"mime type: {mime_type}, tika_compatible: {tika_compatible}", object_id=file_data.object_id)

        # If the file is known to be tika compatible, or is not a binary file
        #   and is also not known source code, and is not an encrypted word doc,
        #   then try to extract text and index it
        if (tika_compatible or not file_is_binary) and not is_source_code and not doc_is_encrypted:
            try:
                if mime_type == "text/plain" and file_data.size > self.plaintext_size_limit:
                    await logger.awarning(f"File is plaintext and over the plaintext_size_limit of {self.plaintext_size_limit}, not performing text processing", object_id=file_data.object_id)
                    enrichments_failure.append(constants.E_TEXT_EXTRACTED)
                else:
                    # use Tika to extract to a new local UUID that references the uploaded Nemesis file text
                    #   specifying that we want to clean the text before saving
                    #   if the file is plaintext, it's just cleaned/processed directly
                    plaintext_file_id = await self.extract_text(file_path=file_path_on_disk,
                                                                object_id=file_data.object_id,
                                                                magic_type=file_magic_type,
                                                                mime_type=mime_type,
                                                                clean_text=True)

                    if plaintext_file_id:
                        file_data.extracted_plaintext = str(plaintext_file_id)
                    enrichments_success.append(constants.E_TEXT_EXTRACTED)
            except Exception as e:
                await logger.aexception(e, message="Exception in running extract_text()")
                enrichments_failure.append(constants.E_TEXT_EXTRACTED)

        # If we can convert the document to a PDF with Gotenberg and the document isn't an encrypted office doc, and it's < 25 megs
        if can_convert_to_pdf and not doc_is_encrypted:
            # use Gotenberg to convert the document to a new local UUID that references the uploaded Nemesis file text
            #   Gotenberg requires an extension, so we have to temporarily rename the file to its original extension
            pdf_size_limit = 25000000
            if (file_data.size > pdf_size_limit):
                await logger.awarning(
                    f"file '{file_data.name}' is over the PDF conversion size limit of  {pdf_size_limit} bytes"
                )
            else:
                orig_filename = file_path_on_disk
                temp_filename = f"{orig_filename}.{file_data.extension}"
                os.rename(orig_filename, temp_filename)

                try:
                    # render Excel docs in landscape
                    landscape = re.match("^.*\\.(xls|xlsx|xlsm)$", file_data.path, re.IGNORECASE) is not None
                    start = time.time()
                    pdf_uuid = await self.convert_to_pdf(temp_filename, landscape)
                    end = time.time()
                    await logger.ainfo(f"Document converted to PDF in {(end - start):.2f} seconds", object_id=file_data.object_id)
                    enrichments_success.append(constants.E_PDF_CONVERSION)

                    if pdf_uuid:
                        file_data.converted_pdf = str(pdf_uuid)
                except Exception as e:
                    await logger.aexception(e, message="Could not convert file to PDF", file_uuid=file_uuid_str)
                    enrichments_failure.append(constants.E_PDF_CONVERSION)

                # restore the original file name
                os.rename(temp_filename, orig_filename)

        ###########################################################
        #
        # Misc processing
        #
        ###########################################################

        # check the file for canaries :smiling_imp:
        if not doc_is_encrypted and tika_compatible:
            if file_data.parsed_data.WhichOneof("data_type") == "office_doc_new":
                canaries = await canary_helpers.get_office_document_canaries(file_path_on_disk)
                file_data.canaries.CopyFrom(canaries)
            else:
                canaries = await canary_helpers.get_file_canaries(file_path_on_disk)
                file_data.canaries.CopyFrom(canaries)

            if file_data.canaries.canaries_present:
                text = ""

                for canary in file_data.canaries.canaries:
                    rule = canary.type
                    urls = ", ".join(canary.data)
                    urls = urls.replace(".", "[.]")
                    text += f"*Rule {rule} :* {urls}\n"

                if not file_previously_processed:
                    await self.alerter.file_data_alert(
                        file_data=file_data,
                        metadata=metadata,
                        title="Possible canaries detected",
                        text=text,
                    )

        # run Yara OPSEC rules on the file
        yara_matches = await self.yara_opsec_scan(file_path_on_disk)
        if isinstance(yara_matches, pb.Error):
            enrichments_failure.append(constants.E_YARA_SCAN)
            await logger.aerror(f"Error in yara_opsec_scan: {yara_matches.error}")
        else:
            enrichments_success.append(constants.E_YARA_SCAN)
            if yara_matches.yara_matches_present and len(yara_matches.yara_matches) > 0:
                file_data.yara_matches.CopyFrom(yara_matches)

                alert_rules = [t.rule_name for t in yara_matches.yara_matches if t.rule_name not in constants.EXCLUDED_YARA_RULES]

                if alert_rules:
                    rule_matches_str = ", ".join(alert_rules)
                    if not file_previously_processed:
                        await self.alerter.file_data_alert(
                            file_data=file_data,
                            metadata=metadata,
                            title="Yara rule match(es)",
                            text=f"*Rules:* {rule_matches_str}",
                        )

        # if the file isn't a binary file (or is a Chromium history file)
        #   run NoseyParker on it for anything we can find
        if not file_is_binary or file_data.parsed_data.WhichOneof("data_type") == "chromium_history":
            try:
                noseyparker_output = helpers.run_noseyparker(file_path_on_disk)
                enrichments_success.append(constants.E_NOSEYPARKER_SCAN)

                if noseyparker_output and len(noseyparker_output.rule_matches) > 0:
                    file_data.noseyparker.CopyFrom(noseyparker_output)
                    if not file_previously_processed:
                        await self.alerter.file_data_alert(
                            file_data=file_data,
                            title="NoseyParker Results",
                            metadata=metadata,
                        )
            except Exception as e:
                await logger.aexception(e, message="Noseyparker scanning failed")
                enrichments_failure.append(constants.E_NOSEYPARKER_SCAN)

        # first check if there's a non-null originating_object_id - this is to prevent an explosion
        #   of files if there are nested archives
        # then if the file is not tika_compatible (this is a hack for "not a new office document format")
        #   call process_archive to decompress the archive and process every
        #   file within it (assuming the decompressed size is below self.extracted_archive_size_limit)
        if (
            (not originating_object_id or originating_object_id == "00000000-0000-0000-0000-000000000000")
            and not tika_compatible
            and helpers.is_archive(file_path_on_disk)
        ):
            if await self.process_archive(file_path_on_disk, file_path, file_data.object_id, metadata):
                enrichments_success.append(constants.E_ARCHIVE_CONTENTS_PROCESSED)
            else:
                enrichments_failure.append(constants.E_ARCHIVE_CONTENTS_PROCESSED)

        # if the file type is a .NET assembly, perform additional analysis (deserialization/etc.)
        if file_data.nemesis_file_type == "dotnet_assembly":
            if not self.dotnet_uri:
                # file_data.analysis = helpers.get "error: DOTNET_URI not defined"
                file_data.extracted_source = "error: DOTNET_URI not defined"
            else:
                # decompile the source and analyze the assembly
                #   we want to use the original object_id instead of the temp file path here
                #   because the dotnet container is downloading the original file from storage
                dotnet_results = await self.process_dotnet(file_data.object_id)

                if dotnet_results:
                    if "error" in dotnet_results["decompilation"]:
                        file_data.extracted_source = dotnet_results["decompilation"]["error"]
                        enrichments_failure.append(constants.E_DOTNET_ANALYSIS)
                    else:
                        enrichments_success.append(constants.E_DOTNET_ANALYSIS)
                        file_data.analysis.CopyFrom(dotnet_results["analysis"])

                        if not file_previously_processed:
                            try:
                                if file_data.analysis.dotnet_analysis.has_deserialization:
                                    await self.alerter.file_data_alert(
                                        file_data=file_data,
                                        metadata=metadata,
                                        title="Potential Deserialization Found",
                                    )
                            except:
                                pass
                            try:
                                if file_data.analysis.dotnet_analysis.has_cmd_execution:
                                    await self.alerter.file_data_alert(
                                        file_data=file_data,
                                        metadata=metadata,
                                        title="Potential Command Execution Found",
                                    )
                            except:
                                pass
                            try:
                                if file_data.analysis.dotnet_analysis.has_remoting:
                                    await self.alerter.file_data_alert(
                                        file_data=file_data,
                                        metadata=metadata,
                                        title="Potential Remoting Found",
                                    )
                            except:
                                pass

                        if "object_id" in dotnet_results["decompilation"] and dotnet_results["decompilation"]["object_id"] is not None:
                            file_data.extracted_source = dotnet_results["decompilation"]["object_id"]
                            with await self.storage.download(uuid.UUID(file_data.extracted_source)) as temp_decomp_file:
                                # if there's extracted source, download the source and run NoseyParker on the extracted source
                                noseyparker_output = helpers.run_noseyparker_on_archive(temp_decomp_file.name)
                                if noseyparker_output:
                                    file_data.noseyparker.CopyFrom(noseyparker_output)
                                    if not file_previously_processed:
                                        await self.alerter.file_data_alert(
                                            file_data=file_data,
                                            title="NoseyParker Results",
                                            metadata=metadata,
                                        )

                else:
                    enrichments_failure.append(constants.E_DOTNET_ANALYSIS)

        file_data.enrichments_success.extend(enrichments_success)
        file_data.enrichments_failure.extend(enrichments_failure)

        return file_data

    @aio.time(Summary("process_archive", "Time spent processing an archive"))  # type: ignore
    async def process_archive(self, archive_file_path_on_disk: str, archive_file_path: str, archive_uuid: str, metadata: pb.Metadata):
        """Processes all the files in a supplied archive.

        If an archive is under the self.extracted_archive_size_limit when decompressed, decompress
        it, upload each file to Nemesis, and publish a new `file_data` topic for each new file
        so each file is processed individually by the pipeline.
        """

        archive_size = helpers.get_archive_size(archive_file_path_on_disk)

        if not (archive_size > 0 and archive_size < self.extracted_archive_size_limit):
            await logger.awarning(
                f"process_archive: '{archive_file_path}' ({archive_file_path_on_disk}) is over the projected decompressed limit of {self.extracted_archive_size_limit} bytes"
            )
            return False

        try:
            tmp_dir = helpers.extract_archive(archive_file_path_on_disk)
        except helpers.FileNotSupportedException:
            logger.info("File is not a supported archive format", file_path_on_disk=archive_file_path_on_disk)
            return False
        except RuntimeError as e:
            if "encrypted, password required for extraction" in str(e):
                logger.info("Archive is encrypted", file_path_on_disk=archive_file_path_on_disk)
                return True
            logger.exception(e, message="RuntimeError extracting archive", file_path_on_disk=archive_file_path_on_disk)
            return False

        processed_files = 0

        for extracted_file_path in pathlib.Path(tmp_dir).rglob("**/*"):
            try:
                extracted_file_size = os.path.getsize(extracted_file_path)

                if os.path.isfile(extracted_file_path) and extracted_file_size > 0:
                    async with TempFile(self.data_download_dir) as temp_file:
                        # Rename the extracted file to a UUID and upload to Nemesis/S3
                        shutil.move(extracted_file_path, temp_file.path)
                        object_id = await self.storage.upload(temp_file.path)

                    # ensure / normalization for the file path
                    extracted_file_path = str(extracted_file_path).replace("\\", "/")

                    # construct the "actual" file path as the original ".../zip_path/this_file"
                    real_extracted_file_path = extracted_file_path.replace(tmp_dir, archive_file_path)

                    file_data_message_pb = pb.FileDataIngestionMessage()

                    # copy in the original archive's metadata
                    file_data_message_pb.metadata.CopyFrom(metadata)

                    file_data_pb = file_data_message_pb.data.add()
                    file_data_pb.object_id = f"{object_id}"
                    file_data_pb.path = real_extracted_file_path
                    file_data_pb.size = extracted_file_size

                    # set the originating object for this file as the UUID from the archive it was extracted from
                    file_data_pb.originating_object_id = archive_uuid

                    # publish this as a new "file_data" message to the queue...
                    await self.out_q_filedata.Send(file_data_message_pb.SerializeToString())

                    await logger.ainfo(f"Submitted extracted file '{real_extracted_file_path}' to Nemesis")
                    processed_files += 1

            except Exception as e:
                await logger.aexception(
                    e, message="process_archive error", extracted_file_path=extracted_file_path, archive_file_path=archive_file_path
                )
                return False

        await logger.ainfo("Files processed from archive", archive_file_path=archive_file_path, processed_files=processed_files)

        # clean up the extracted directory
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return True

    @aio.time(Summary("process_file_data", "Time spent processing a file_data topic"))  # type: ignore
    async def process_file_data(self, event: pb.FileDataIngestionMessage):
        """Main function to process file_data events."""

        for data in event.data:
            file_data_enriched_message = pb.FileDataEnrichedMessage()

            # copy in the original message's metadata
            file_data_enriched_message.metadata.CopyFrom(event.metadata)

            object_id = data.object_id
            originating_object_id = data.originating_object_id
            file_path = data.path

            # enrich the data, passing the new file_data_enriched object so we don't have to make a copy later
            start_time = datetime.now()

            structlog.contextvars.bind_contextvars(
                file_path=file_path,
                object_id=object_id,
            )

            try:
                file_data_enriched = await self.process_file(object_id, originating_object_id, file_path, event.metadata)
                file_data_enriched_message.data.extend([file_data_enriched])

                await logger.ainfo("Finished processing file", duration=str(datetime.now() - start_time))

                await self.out_q_filedataenriched.Send(file_data_enriched_message.SerializeToString())
            except Exception as e:
                await logger.aexception(e, message="process_file error", file_uuid=object_id)
                return helpers.nemesis_error(f"process_file error for {object_id} : {e}")

    @aio.time(Summary("process_file_data_enriched", "Time spent processing a file_data_enriched topic"))  # type: ignore
    async def process_file_data_enriched(self, event: pb.FileDataEnrichedMessage):
        """Main function to process file_data_enriched events."""

        for data in event.data:
            structlog.contextvars.bind_contextvars(
                object_id=data.object_id,
                file_path=data.name,
            )

            # if this enriched file has extracted plaintext, emit a file_data_plaintext_message
            if data.extracted_plaintext and data.extracted_plaintext != "":
                file_data_plaintext_message = pb.FileDataPlaintextMessage()
                file_data_plaintext_message.metadata.CopyFrom(event.metadata)
                file_uuid_str = data.extracted_plaintext
                start_time = datetime.now()

                plaintext_result = await self.process_plaintext_from_file_data_enriched(data, file_data_plaintext_message)

                if plaintext_result:
                    await logger.ainfo(f"{file_uuid_str} processed in: {datetime.now() - start_time}")
                    await self.out_q_filedataplaintext.Send(file_data_plaintext_message.SerializeToString())

            # if this file is source code, emit a file_data_sourcecode message
            elif data.is_source_code:
                file_data_sourcecode_message = pb.FileDataSourcecodeMessage()
                file_data_sourcecode_message.metadata.CopyFrom(event.metadata)
                file_data_sourcecode = file_data_sourcecode_message.data.add()
                file_data_sourcecode.object_id = data.object_id
                file_data_sourcecode.path = data.path
                file_data_sourcecode.name = data.name
                file_data_sourcecode.extension = data.extension
                file_data_sourcecode.language = helpers.map_extension_to_language(data.extension)
                file_data_sourcecode.size = data.size
                await self.out_q_filedatasourcecode.Send(file_data_sourcecode_message.SerializeToString())

    async def yara_opsec_scan(self, file_path: str):
        """
        Scans the given file path with all current yara OPSEC rules.

        Any matches are returned. If the file doesn't exist, we attempt to
        download it the Nemesis datastore.
        """

        yara_matches = pb.YaraMatches()

        if os.path.exists(file_path):
            try:
                for match in self.yara_rules.match(file_path):
                    yara_matches.yara_matches_present = True
                    yara_match = pb.YaraMatches.YaraMatch()
                    yara_match.rule_file = match.namespace
                    yara_match.rule_name = match.rule
                    if yara_match.rule_name in self.yara_rule_definitions:
                        yara_match.rule_text = self.yara_rule_definitions[yara_match.rule_name]
                    if hasattr(match, 'meta') and "description" in match.meta:
                        yara_match.rule_description = match.meta["description"]
                    if hasattr(match, 'strings'):
                        for yara_string in match.strings:
                            yara_string_match = pb.YaraMatches.YaraStringMatch()
                            yara_string_match.identifier = yara_string.identifier
                            for instance in yara_string.instances:
                                yara_string_match_instance = pb.YaraMatches.YaraStringMatchInstance()
                                yara_string_match_instance.matched_data = bytes(instance.matched_data)
                                yara_string_match_instance.offset = instance.offset
                                yara_string_match_instance.length = instance.matched_length
                                yara_string_match.yara_string_match_instances.extend([yara_string_match_instance])
                            yara_match.rule_string_matches.extend([yara_string_match])
                    yara_matches.yara_matches.extend([yara_match])
            except Exception as e:
                yara_matches = helpers.nemesis_error(f"yara_scan_file error for {file_path} : {e}")
                await logger.aexception(e, message="yara_scan_file error", file_path=file_path)
        else:
            try:
                # try to download the file from the nemesis API
                file_uuid = uuid.UUID(file_path)
                with await self.storage.download(file_uuid) as temp_file:
                    self.yara_rules.match(temp_file.name)
            except Exception as e:
                yara_matches = helpers.nemesis_error(f"yara_scan_file error for {file_path} : {e}")
                await logger.aexception(e, message="yara_scan_file error", file_path=file_path)
            finally:
                # clean up the local file if it exists
                if os.path.exists(file_path):
                    os.remove(file_path)

        return yara_matches

    async def extract_text(self, file_path: str, object_id: str, magic_type: str, mime_type: str, clean_text: bool = True) -> Optional[uuid.UUID]:
        """Extracts text from a file, and if there's text, returns a Nemesis File UUID."""

        if mime_type == "text/plain":
            await logger.ainfo("File is 'text/plain', not using Tika", object_id=object_id, magic_type=magic_type, mime_type=mime_type)
            if clean_text and "ascii" not in magic_type.lower():
                if "utf-16" in magic_type.lower():
                    with open(file_path, "r", encoding="utf-16") as f:
                        text = anyascii(re.sub(r'([\s][*\n]+[\s]*)+', '\n', f.read()))
                elif "utf-32" in magic_type.lower():
                    with open(file_path, "r", encoding="utf-32") as f:
                        text = anyascii(re.sub(r'([\s][*\n]+[\s]*)+', '\n', f.read()))
                else:
                    with open(file_path, "r") as f:
                        text = anyascii(re.sub(r'([\s][*\n]+[\s]*)+', '\n', f.read()))
                with tempfile.NamedTemporaryFile(mode="w") as plaintext_file:
                    plaintext_file.write(text)
                    plaintext_file.seek(0)
                    plaintext_file_uuid = await self.storage.upload(plaintext_file.name)
                    return plaintext_file_uuid
            else:
                # if it's straight ascii, just return the existing object_id
                return object_id
        else:
            text = await self.text_extractor.extract(file_path)
            if text is None:
                await logger.adebug("No text extracted", file_path=file_path)
                return None

            # Write the extracted text to a temporary file and upload it to Nemesis
            with tempfile.NamedTemporaryFile(mode="w") as plaintext_file:

                if clean_text:
                    # collapse multiple newlines and transliterate Unicode to ascii
                    text = anyascii(re.sub(r'([\s][*\n]+[\s]*)+', '\n', text))

                plaintext_file.write(text)
                plaintext_file.seek(0)

                extractedtext_file_uuid = await self.storage.upload(plaintext_file.name)
                return extractedtext_file_uuid

    async def convert_to_pdf(self, file_path: str, landscape: bool = False) -> Optional[uuid.UUID]:
        """Calls self.gotenberg_uri to convert the supplied document to a PDF.

        The PDF is written to a new UUID, uploaded to S3, and the UUID is returned.
        """

        with open(file_path, "rb") as file:
            if landscape:
                files = {"file": file, "landscape": "true"}
            else:
                files = {"file": file}
            url = f"{self.gotenberg_uri}forms/libreoffice/convert"

            session_timeout = aiohttp.ClientTimeout(total=None, sock_connect=(60*3), sock_read=(60*3))
            async with aiohttp.ClientSession(timeout=session_timeout) as session:
                async with TempFile(self.data_download_dir) as temp_file:
                    async with session.post(url, data=files) as resp:
                        resp.raise_for_status()

                        with open(temp_file.path, "wb") as f:
                            async for chunk in resp.content.iter_chunked(self.chunk_size):
                                f.write(chunk)

                        if os.path.getsize(temp_file.path) > 0:
                            pdf_file_uuid = await self.storage.upload(temp_file.path)
                            return pdf_file_uuid
                        else:
                            await logger.awarning(f"Result {temp_file.path} is 0 bytes")
                            return None

    async def update_cracklist(self, object_id: str, client_id: str) -> bool:
        """Calls self.crack_list_uri to update the cracklist with the current plaintext file.

        client_id is a unique identifier for the engagement/client
        """

        try:
            data = {"object_id": object_id, "client_id": client_id}
            url = f"{self.crack_list_uri}add?length_filter=true"

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data) as resp:
                    resp.raise_for_status()
                    return True

        except Exception as e:
            await logger.aexception(e, message="Error calling cracklist", file_uuid=object_id)
            return False

    async def process_dotnet(self, file_path: str) -> Optional[dict]:
        """Calls the self.dotnet_uri/process api endpoint to decompile the supplied .NET assembly."""

        try:
            data = {"object_id": file_path}
            # headers = {"Content-type": "application/json", "Accept": "text/plain"}
            url = f"{self.dotnet_uri}process"

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data) as resp:
                    resp.raise_for_status()
                    response = await resp.json()

                    results = {}
                    results["decompilation"] = response["decompilation"]

                    # extract out all of the json'ified analysis output
                    data = response["analysis"]

                    analysis = pb.Analysis()

                    if data["RemotingChannels"]:
                        analysis.dotnet_analysis.remoting_channels.extend(data["RemotingChannels"])

                    analysis.dotnet_analysis.is_wcf_server = data["IsWCFServer"]
                    analysis.dotnet_analysis.is_wcf_client = data["IsWCFClient"]

                    for k, v in data["SerializationGadgetCalls"].items():
                        for temp in v:
                            analysis.dotnet_analysis.has_deserialization = True
                            gadget_call = analysis.dotnet_analysis.serialization_gadget_calls.add()
                            gadget_call.gadget_name = k
                            gadget_call.method_name = temp["MethodName"] if temp["MethodName"] else ""
                            gadget_call.filter_level = temp["FilterLevel"] if temp["FilterLevel"] else ""

                    for k, v in data["WcfServerCalls"].items():
                        for temp in v:
                            analysis.dotnet_analysis.has_remoting = True
                            gadget_call = analysis.dotnet_analysis.wcf_server_calls.add()
                            gadget_call.gadget_name = k
                            gadget_call.method_name = temp["MethodName"] if temp["MethodName"] else ""
                            gadget_call.filter_level = temp["FilterLevel"] if temp["FilterLevel"] else ""

                    for k, v in data["ClientCalls"].items():
                        for temp in v:
                            analysis.dotnet_analysis.has_remoting = True
                            gadget_call = analysis.dotnet_analysis.client_calls.add()
                            gadget_call.gadget_name = k
                            gadget_call.method_name = temp["MethodName"] if temp["MethodName"] else ""
                            gadget_call.filter_level = temp["FilterLevel"] if temp["FilterLevel"] else ""

                    for k, v in data["RemotingCalls"].items():
                        for temp in v:
                            analysis.dotnet_analysis.has_remoting = True
                            gadget_call = analysis.dotnet_analysis.remoting_calls.add()
                            gadget_call.gadget_name = k
                            gadget_call.method_name = temp["MethodName"] if temp["MethodName"] else ""
                            gadget_call.filter_level = temp["FilterLevel"] if temp["FilterLevel"] else ""

                    for k, v in data["ExecutionCalls"].items():
                        for temp in v:
                            analysis.dotnet_analysis.has_cmd_execution = True
                            gadget_call = analysis.dotnet_analysis.cmd_execution_calls.add()
                            gadget_call.gadget_name = k
                            gadget_call.method_name = temp["MethodName"] if temp["MethodName"] else ""

                    results["analysis"] = analysis

                    return results

        except Exception as e:
            await logger.aexception(e, message="process_dotnet: error", file_path=file_path)
            return None

    async def process_plaintext_from_file_data_enriched(
        self, file_data: pb.FileDataEnriched, file_data_plaintext_message: pb.FileDataPlaintextMessage
    ):
        """Processes extracted file plaintext from a file_data_enriched file.

        Takes a file_data_enriched message and builds an additional enriched file_data_plaintext
        that's put back into the queue if `extractedPlaintext` is specified in the file_data_enriched
        message.
        """

        if not file_data.HasField("extracted_plaintext"):
            return False

        # file UUID of the extracted plaintext file
        nemesis_uuid = file_data.extracted_plaintext

        # the original path of the downloaded file
        originating_object_path = file_data.path

        # the original size of the downloaded file
        originating_object_size = file_data.size

        file_data_plaintext = file_data_plaintext_message.data.add()
        file_data_plaintext.object_id = nemesis_uuid
        file_data_plaintext.originating_object_path = originating_object_path
        file_data_plaintext.originating_object_id = file_data.object_id
        file_data_plaintext.originating_object_size = originating_object_size

        if file_data.converted_pdf:
            # if the file was converted to a PDF, set save that UUID for later reference/display
            file_data_plaintext.originating_object_converted_pdf = file_data.converted_pdf
        elif file_data.path.endswith(".pdf"):
            # if the file WAS a PDF, set save that UUID for later reference/display
            file_data_plaintext.originating_object_converted_pdf = file_data.object_id

        enrichments_success = []
        enrichments_failure = []

        try:
            # download the file from the nemesis API
            with await self.storage.download(uuid.UUID(nemesis_uuid)) as temp_file:
                word_count = 0
                size = 0

                with open(temp_file.name, "rb") as f:
                    # chunking to handle large files
                    while chunk := f.read(self.chunk_size):
                        word_count += len(chunk.split())
                        size += len(chunk)

                file_data_plaintext.word_count = word_count
                file_data_plaintext.size = size

                # update the cracking list with this plaintext file + the project ID
                if size > self.plaintext_size_limit:
                    await logger.awarning(f"Plaintext object is over the plaintext_size_limit of {self.plaintext_size_limit}, not adding to cracklist", object_id=nemesis_uuid)
                else:
                    success = await self.update_cracklist(nemesis_uuid, file_data_plaintext_message.metadata.project)

                    if success:
                        enrichments_success.append(constants.E_UPDATE_CRACKLIST)
                    else:
                        enrichments_failure.append(constants.E_UPDATE_CRACKLIST)

                # run NoseyParker on the plaintext for anything we can find
                try:
                    noseyparker_output = helpers.run_noseyparker(temp_file.name)

                    enrichments_success.append(constants.E_NOSEYPARKER_SCAN_TEXT)
                    if noseyparker_output:
                        file_data_plaintext.noseyparker.CopyFrom(noseyparker_output)
                except Exception as e:
                    await logger.aexception(e, message="Exception running noseyparker in process_file_plaintext")
                    enrichments_failure.append(constants.E_NOSEYPARKER_SCAN_TEXT)

        except Exception as e:
            await logger.aexception(e, message="Exception in process_file_plaintext")

        if file_data_plaintext:
            file_data_plaintext.enrichments_success.extend(enrichments_success)
            file_data_plaintext.enrichments_failure.extend(enrichments_failure)

        return True
