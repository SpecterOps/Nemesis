# Standard Libraries
import asyncio
import ipaddress
import ntpath
import re
import uuid
from typing import Any, Optional, Self, Tuple

# 3rd Party Libraries
import nemesiscommon.constants as constants
import nemesispb.nemesis_pb2 as pb
import structlog
from enrichment.lib.nemesis_db import (  # AuthenticationData,; ChromiumCookie,; ChromiumDownload,; ChromiumHistoryEntry,; ChromiumLogin,; ChromiumStateFile,; DpapiBlob,; ExtractedHash,; FileDataEnriched,; FileInfo,; FileInfoDataEnriched,; NetworkConnection,
    Agent,
    HostAgent,
    NamedPipe,
    NemesisDb,
    OperationType,
    Project,
)
from enrichment.tasks.postgres_connector.registry_watcher import RegistryWatcher
from google.protobuf.json_format import MessageToDict
from nemesiscommon.messaging import MessageQueueConsumerInterface
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger(module=__name__)


class HostMappingData:
    short_name: Optional[str]
    long_name: Optional[str]
    ip_address: Optional[str]

    _ip_regex: re.Pattern

    def __init__(self, short_name: Optional[str], long_name: Optional[str], ip_address: Optional[str]):
        self.short_name = short_name
        self.long_name = long_name
        self.ip_address = ip_address

    @staticmethod
    def from_str(source: str):
        # Check if the source is an IP address

        if HostMappingData.__is_ipv4_address(source):
            return HostMappingData(None, None, source)

        if HostMappingData.__is_fqdn(source):
            return HostMappingData(None, source, None)

        return HostMappingData(source, None, None)

    @staticmethod
    def __is_fqdn(hostname: str):
        # Very simplistic check to see if the host is an FQDN: does it have a dot in it?
        return "." in hostname

    @staticmethod
    def __is_ipv4_address(address: str):
        try:
            ipaddress.IPv4Network(address)
            return True
        except ValueError:
            return False


class PostgresConnector(TaskInterface):
    db: NemesisDb
    reg_watcher: RegistryWatcher

    # Queues
    auth_data_q: MessageQueueConsumerInterface
    chromium_cookies_q: MessageQueueConsumerInterface
    chromium_downloads_q: MessageQueueConsumerInterface
    chromium_history_q: MessageQueueConsumerInterface
    chromium_logins_q: MessageQueueConsumerInterface
    chromium_state_file_processed_q: MessageQueueConsumerInterface
    dpapi_blob_processed_q: MessageQueueConsumerInterface
    extracted_hash_q: MessageQueueConsumerInterface
    file_data_enriched_q: MessageQueueConsumerInterface
    file_info_q: MessageQueueConsumerInterface
    named_pipe_q: MessageQueueConsumerInterface
    network_connection_q: MessageQueueConsumerInterface
    path_list_q: MessageQueueConsumerInterface
    registry_value_q: MessageQueueConsumerInterface
    service_enriched_q: MessageQueueConsumerInterface

    def __init__(
        self,
        db: NemesisDb,
        reg_watcher: RegistryWatcher,
        auth_data_q: MessageQueueConsumerInterface,
        chromium_cookies_q: MessageQueueConsumerInterface,
        chromium_downloads_q: MessageQueueConsumerInterface,
        chromium_history_q: MessageQueueConsumerInterface,
        chromium_logins_q: MessageQueueConsumerInterface,
        chromium_state_file_processed_q: MessageQueueConsumerInterface,
        dpapi_blob_processed_q: MessageQueueConsumerInterface,
        extracted_hash_q: MessageQueueConsumerInterface,
        file_data_enriched_q: MessageQueueConsumerInterface,
        file_info_q: MessageQueueConsumerInterface,
        named_pipe_q: MessageQueueConsumerInterface,
        network_connection_q: MessageQueueConsumerInterface,
        path_list_q: MessageQueueConsumerInterface,
        registry_value_q: MessageQueueConsumerInterface,
        service_enriched_q: MessageQueueConsumerInterface,
    ):
        self.db = db
        self.reg_watcher = reg_watcher

        self.auth_data_q = auth_data_q
        self.chromium_cookies_q = chromium_cookies_q
        self.chromium_downloads_q = chromium_downloads_q
        self.chromium_history_q = chromium_history_q
        self.chromium_logins_q = chromium_logins_q
        self.chromium_state_file_processed_q = chromium_state_file_processed_q
        self.dpapi_blob_processed_q = dpapi_blob_processed_q
        self.extracted_hash_q = extracted_hash_q
        self.file_data_enriched_q = file_data_enriched_q
        self.file_info_q = file_info_q
        self.named_pipe_q = named_pipe_q
        self.network_connection_q = network_connection_q
        self.path_list_q = path_list_q
        self.registry_value_q = registry_value_q
        self.service_enriched_q = service_enriched_q

    async def run(self) -> None:
        await logger.ainfo("Starting the Postgres Connector")

        await asyncio.gather(
            # self.auth_data_q.Read(self.process_auth_data),  # type: ignore
            # self.chromium_cookies_q.Read(self.process_chromium_cookie),  # type: ignore
            # self.chromium_downloads_q.Read(self.process_chromium_download),  # type: ignore
            # self.chromium_history_q.Read(self.process_chromium_history),  # type: ignore
            # self.chromium_logins_q.Read(self.process_chromium_login),  # type: ignore
            # self.chromium_state_file_processed_q.Read(self.process_chromium_state_file_processed),  # type: ignore
            # self.dpapi_blob_processed_q.Read(self.process_dpapi_blob),  # type: ignore
            # self.extracted_hash_q.Read(self.process_extracted_hash),  # type: ignore
            # self.file_data_enriched_q.Read(self.process_file_data_enriched),  # type: ignore
            # self.file_info_q.Read(self.process_file_info),  # type: ignore
            # self.path_list_q.Read(self.process_path_list),  # type: ignore
            # self.registry_value_q.Read(self.process_registry_value),  # type: ignore
            self.named_pipe_q.Read(self.process_named_pipe),  # type: ignore
            # self.service_enriched_q.Read(self.process_service),  # type: ignore
            # self.network_connection_q.Read(self.process_network_connection),  # type: ignore
        )
        await asyncio.Future()

    # @aio.time(Summary("process_chromium_history", "Time spent processing a chromium_history queue"))  # type: ignore
    # async def process_chromium_history(self, event: pb.ChromiumHistoryMessage):
    #     """Main function to process chromium_history queue."""

    #     m = event.metadata
    #     await self.ensure_project_exists(m)

    #     for i in event.data:
    #         data = ChromiumHistoryEntry(
    #             m.agent_id,
    #             m.project,
    #             m.source,
    #             m.timestamp.ToDatetime(),
    #             m.expiration.ToDatetime(),
    #             i.user_data_directory,
    #             i.username,
    #             i.browser,
    #             i.url,
    #             i.title,
    #             i.visit_count,
    #             i.typed_count,
    #             i.last_visit_time.ToDatetime(),
    #         )
    #         if i.originating_object_id:
    #             data.originating_object_id = uuid.UUID(i.originating_object_id)

    #         try:
    #             await self.db.add_chromium_history_entry(data)
    #         except Exception as e:
    #             logger.exception(e, message="Error adding chrome history entry", data=data)

    # @aio.time(Summary("process_chromium_download", "Time spent processing a chromium_download queue"))  # type: ignore
    # async def process_chromium_download(self, event: pb.ChromiumDownloadMessage):
    #     """Main function to process chromium_download queue."""

    #     m = event.metadata
    #     await self.ensure_project_exists(m)

    #     for i in event.data:
    #         data = ChromiumDownload(
    #             m.agent_id,
    #             m.project,
    #             m.source,
    #             m.timestamp.ToDatetime(),
    #             m.expiration.ToDatetime(),
    #             i.user_data_directory,
    #             i.username,
    #             i.browser,
    #             i.url,
    #             i.download_path,
    #             i.start_time.ToDatetime(),
    #             i.end_time.ToDatetime(),
    #             i.total_bytes,
    #             i.danger_type,
    #         )
    #         if i.originating_object_id:
    #             data.originating_object_id = uuid.UUID(i.originating_object_id)

    #         await self.db.add_chromium_download(data)

    # @aio.time(Summary("process_chromium_login_processed", "Time spent processing a chromium_login_processed queue"))  # type: ignore
    # async def process_chromium_login(self, event: pb.ChromiumLoginMessage):
    #     """Main function to process chromium_login queue."""

    #     m = event.metadata
    #     await self.ensure_project_exists(m)

    #     for i in event.data:
    #         data = ChromiumLogin(
    #             m.agent_id,
    #             m.project,
    #             m.source,
    #             m.timestamp.ToDatetime(),
    #             m.expiration.ToDatetime(),
    #             i.user_data_directory,
    #             i.username,
    #             i.browser,
    #             i.origin_url,
    #             i.username_value,
    #             i.signon_realm,
    #             i.date_created.ToDatetime(),
    #             i.date_last_used.ToDatetime(),
    #             i.date_password_modified.ToDatetime(),
    #             i.times_used,
    #             i.password_value_enc,
    #             i.encryption_type,
    #             i.masterkey_guid,
    #             i.is_decrypted,
    #             i.password_value_dec,
    #         )
    #         if i.originating_object_id:
    #             data.originating_object_id = uuid.UUID(i.originating_object_id)

    #         await self.db.add_chromium_login(data)

    # @aio.time(Summary("process_chromium_cookie_processed", "Time spent processing a chromium_cookie queue"))  # type: ignore
    # async def process_chromium_cookie(self, event: pb.ChromiumCookieMessage):
    #     """Main function to process chromium_cookie queue."""

    #     m = event.metadata
    #     await self.ensure_project_exists(m)

    #     for i in event.data:
    #         data = ChromiumCookie(
    #             m.agent_id,
    #             m.project,
    #             m.source,
    #             m.timestamp.ToDatetime(),
    #             m.expiration.ToDatetime(),
    #             i.user_data_directory,
    #             i.username,
    #             i.browser,
    #             i.host_key,
    #             i.name,
    #             i.path,
    #             i.creation.ToDatetime(),
    #             i.expires.ToDatetime(),
    #             i.last_access.ToDatetime(),
    #             i.last_update.ToDatetime(),
    #             i.is_secure,
    #             i.is_httponly,
    #             i.is_session,
    #             i.samesite,
    #             i.source_port,
    #             i.value_enc,
    #             i.encryption_type,
    #             i.masterkey_guid,
    #             i.is_decrypted,
    #             i.value_dec,
    #         )

    #         if not data.originating_object_id or data.masterkey_guid == "":
    #             data.masterkey_guid = "00000000-0000-0000-0000-000000000000"

    #         if i.originating_object_id:
    #             data.originating_object_id = uuid.UUID(i.originating_object_id)
    #         else:
    #             data.originating_object_id = uuid.UUID("00000000-0000-0000-0000-000000000000")

    #         await self.db.add_chromium_cookie(data)

    # @aio.time(Summary("process_chromium_state_file_processed", "Time spent processing a chromium_state_file queue"))  # type: ignore
    # async def process_chromium_state_file_processed(self, event: pb.ChromiumStateFileMessage):
    #     """Main function to process chromium_state_file queue."""

    #     m = event.metadata
    #     await self.ensure_project_exists(m)

    #     for i in event.data:
    #         data = ChromiumStateFile(
    #             m.agent_id,
    #             m.project,
    #             m.source,
    #             m.timestamp.ToDatetime(),
    #             m.expiration.ToDatetime(),
    #             i.user_data_directory,
    #             i.username,
    #             i.browser,
    #             i.installation_date.ToDatetime(),
    #             i.launch_count,
    #             i.masterkey_guid,
    #             i.key_bytes_enc,
    #             i.app_bound_fixed_data_enc,
    #             i.is_decrypted,
    #             i.key_bytes_dec,
    #             i.app_bound_fixed_data_dec,
    #         )
    #         if i.originating_object_id:
    #             data.originating_object_id = uuid.UUID(i.originating_object_id)

    #         await self.db.add_chromium_state_file(data)

    # @aio.time(Summary("process_authentication_data", "Time spent processing an authentication_data queue"))  # type: ignore
    # async def process_auth_data(self, event: pb.AuthenticationDataIngestionMessage):
    #     """Main function to process authentication_data queue."""

    #     m = event.metadata
    #     await self.ensure_project_exists(m)

    #     for i in event.data:
    #         if not i.originating_object_id:
    #             i.originating_object_id = "00000000-0000-0000-0000-000000000000"

    #         data = AuthenticationData(
    #             m.agent_id,
    #             m.project,
    #             m.source,
    #             m.timestamp.ToDatetime(),
    #             m.expiration.ToDatetime(),
    #             i.data,
    #             i.type,
    #             i.is_file,
    #             i.uri,
    #             i.username,
    #             i.notes,
    #             uuid.UUID(i.originating_object_id),
    #         )

    #         await self.db.add_authentication_data(data)

    # @aio.time(Summary("process_extracted_hash", "Time spent processing an extracted_hash queue"))  # type: ignore
    # async def process_extracted_hash(self, event: pb.ExtractedHashMessage):
    #     """Main function to process extracted_hash queue."""

    #     await self.ensure_project_exists(event.metadata)

    #     for i in event.data:
    #         data = ExtractedHash(
    #             project_id=event.metadata.project,
    #             agent_id=event.metadata.agent_id,
    #             source=event.metadata.source,
    #             timestamp=event.metadata.timestamp.ToDatetime(),
    #             expiration=event.metadata.expiration.ToDatetime(),
    #             hash_type=i.hash_type,
    #             hash_value=i.hash_value,
    #             hashcat_formatted_value=i.hashcat_formatted_value,
    #             is_cracked=i.is_cracked,
    #             checked_against_top_passwords=i.checked_against_top_passwords,
    #             plaintext_value=i.plaintext_value,
    #         )

    #         if i.originating_object_id:
    #             data.originating_object_id = uuid.UUID(i.originating_object_id)

    #         await self.db.add_extracted_hash(data)

    # @aio.time(Summary("postgresconnector_process_dpapi_blob", "Time spent processing a dpapi_blob queue"))  # type: ignore
    # async def process_dpapi_blob(self, event: pb.DpapiBlobMessage):
    #     """Main function to process dpapi_blob messages."""

    #     await self.ensure_project_exists(event.metadata)

    #     for i in event.data:
    #         if i.originating_object_id:
    #             originating_object_id = uuid.UUID(i.originating_object_id)
    #         else:
    #             originating_object_id = uuid.UUID("00000000-0000-0000-0000-000000000000")
    #         if i.originating_registry_id:
    #             originating_registry_id = uuid.UUID(i.originating_registry_id)
    #         else:
    #             originating_registry_id = uuid.UUID("00000000-0000-0000-0000-000000000000")

    #         d = DpapiBlob(
    #             project_id=event.metadata.project,
    #             agent_id=event.metadata.agent_id,
    #             source=event.metadata.source,
    #             timestamp=event.metadata.timestamp.ToDatetime(),
    #             expiration=event.metadata.expiration.ToDatetime(),
    #             dpapi_blob_id=i.dpapi_blob_id,
    #             is_decrypted=i.is_decrypted,
    #             is_file=i.is_file,
    #             masterkey_guid=uuid.UUID(i.masterkey_guid),
    #             originating_object_id=originating_object_id,
    #             originating_registry_id=originating_registry_id,
    #         )

    #         if i.dec_data_bytes:
    #             d.dec_data_bytes = i.dec_data_bytes
    #         if i.dec_data_object_id:
    #             d.dec_data_object_id = uuid.UUID(i.dec_data_object_id)
    #         if i.enc_data_bytes:
    #             d.enc_data_bytes = i.enc_data_bytes
    #         if i.enc_data_object_id:
    #             d.enc_data_object_id = uuid.UUID(i.enc_data_object_id)

    #         await self.db.add_dpapi_blob(d)

    # @aio.time(Summary("process_registry_value", "Time spent processing a registry_value message"))  # type: ignore
    # async def process_registry_value(self, event: pb.RegistryValueIngestionMessage):
    #     """Adds a registry value to the database anytime a new one is added to Nemesis.

    #     Args:
    #         event (pb.RegistryValueIngestionMessage): The message containing the registry value(s) to add.
    #     """
    #     await self.ensure_project_exists(event.metadata)
    #     await self.reg_watcher.process_registry_value(event)

    # @aio.time(Summary("process_path_list", "Time spent processing a path_list message"))  # type: ignore
    # async def process_path_list(self, event: pb.PathListIngestionMessage):
    #     """Adds a path list to the database anytime a new one is added to Nemesis.

    #     Args:
    #         event (pb.PathListIngestionMessage): The message containing the path list(s) to add.
    #     """
    #     m = event.metadata
    #     await self.ensure_project_exists(m)

    #     for data in event.data:
    #         path = data.path

    #         if path.contains("\\") and not path.endswith("\\"):
    #             path = f"{path}\\"
    #         elif path.contains("/") and not path.endswith("/"):
    #             path = f"{path}/"

    #         if re.match(r"^([a-zA-Z]{1}:){0,1}[\\\/].*", path):
    #             # this is a file system path

    #             for item in data.items:
    #                 if item.endswith("\\") or item.endswith("/"):
    #                     object_type = "folder"
    #                 else:
    #                     object_type = "file"

    #                 f = FileInfo(
    #                     m.agent_id,
    #                     m.project,
    #                     m.source,
    #                     m.timestamp.ToDatetime(),
    #                     m.expiration.ToDatetime(),
    #                     path=f"{path}{item}",
    #                     name=item,
    #                     type=object_type,
    #                 )

    #                 await self.db.add_filesystem_object(f)
    #         else:
    #             await logger.awarning("Unhandled path", path=path)
    #         # elif re.match("^(HKCR|HKCU|HKLM|HKU|HKCC):.*", path, re.IGNORECASE):
    #         #     # TODO: registry hive path
    #         #     pass
    #         # elif re.match("^//.+/.*", path):
    #         #     # TODO: remote file path
    #         #     pass

    # @aio.time(Summary("process_file_info", "Time spent processing a file_info message"))  # type: ignore
    # async def process_file_info(self, event: pb.FileInformationIngestionMessage):
    #     """Adds file information to the database anytime a new one is added to Nemesis.

    #     Args:
    #         event (pb.FileInformationIngestionMessage): The message containing the file information(s) to add.
    #     """
    #     m = event.metadata
    #     await self.ensure_project_exists(m)

    #     for data in event.data:
    #         path = data.path
    #         name = ntpath.basename(path)
    #         temp = ntpath.splitext(path)
    #         if len(temp) > 1:
    #             extension = temp[-1]
    #         else:
    #             extension = ""

    #         if re.match(r"^([a-zA-Z]{1}:){0,1}[\\\/].*", path):
    #             # this is a file system path

    #             f = FileInfo(
    #                 m.agent_id,
    #                 m.project,
    #                 m.source,
    #                 m.timestamp.ToDatetime(),
    #                 m.expiration.ToDatetime(),
    #                 path=data.path,
    #                 name=name,
    #                 extension=extension,
    #                 type=data.type,
    #                 size=data.size,
    #                 access_time=data.access_time.ToDatetime(),
    #                 creation_time=data.creation_time.ToDatetime(),
    #                 modification_time=data.modification_time.ToDatetime(),
    #                 owner=data.owner,
    #                 sddl=data.sddl,
    #                 version_info=data.version_info,
    #             )

    #             await self.db.add_filesystem_object(f)
    #         else:
    #             await logger.awarning("Unhandled path", path=path)

    # @aio.time(Summary("process_file_data_enriched_postgres", "Time spent processing a process_file_data_enriched message"))  # type: ignore
    # async def process_file_data_enriched(self, event: pb.FileDataEnrichedMessage):
    #     """Adds file information to the database anytime a new one is added to Nemesis.

    #     Args:
    #         event (pb.FileDataEnrichedMessage): The message containing the file to add.
    #     """
    #     m = event.metadata
    #     await self.ensure_project_exists(m)

    #     for data in event.data:
    #         path = data.path
    #         name = ntpath.basename(path)
    #         temp = ntpath.splitext(path)
    #         if len(temp) > 1:
    #             extension = temp[-1]
    #         else:
    #             extension = ""

    #         # first add a basic file info entry
    #         f = FileInfoDataEnriched(
    #             m.agent_id,
    #             m.project,
    #             m.source,
    #             m.timestamp.ToDatetime(),
    #             m.expiration.ToDatetime(),
    #             path=data.path,
    #             name=name,
    #             extension=extension,
    #             size=data.size,
    #             magic_type=data.magic_type,
    #             nemesis_file_id=data.object_id,
    #         )
    #         await self.db.add_filesystem_object_from_enriched(f)

    #         file = MessageToDict(data, preserving_proto_field_name=True)
    #         tags = await self.get_tags(file)

    #         # fill in some defaults
    #         if not data.converted_pdf:
    #             data.converted_pdf = "00000000-0000-0000-0000-000000000000"
    #         if not data.extracted_plaintext:
    #             data.extracted_plaintext = "00000000-0000-0000-0000-000000000000"
    #         if not data.extracted_source:
    #             data.extracted_source = "00000000-0000-0000-0000-000000000000"
    #         if not data.originating_object_id:
    #             data.originating_object_id = "00000000-0000-0000-0000-000000000000"

    #         # then add a processed data entry
    #         f = FileDataEnriched(
    #             m.agent_id,
    #             m.project,
    #             m.source,
    #             m.timestamp.ToDatetime(),
    #             m.expiration.ToDatetime(),
    #             object_id=data.object_id,
    #             path=data.path,
    #             name=name,
    #             size=data.size,
    #             md5=data.hashes.md5,
    #             sha1=data.hashes.sha1,
    #             sha256=data.hashes.sha256,
    #             nemesis_file_type=data.nemesis_file_type,
    #             magic_type=data.magic_type,
    #             converted_pdf_id=data.converted_pdf,
    #             extracted_plaintext_id=data.extracted_plaintext,
    #             extracted_source_id=data.extracted_source,
    #             originating_object_id=data.originating_object_id,
    #             tags=tags,
    #         )

    #         await self.db.add_file_data_enriched(f)

    # @aio.time(Summary("process_network_connection", "Time spent processing an network_connection queue"))  # type: ignore
    # async def process_network_connection(self, event: pb.NetworkConnectionIngestionMessage):
    #     """Main function to process network_connection queue."""

    #     await self.ensure_project_exists(event.metadata)

    #     for i in event.data:
    #         data = NetworkConnection(
    #             project_id=event.metadata.project,
    #             agent_id=event.metadata.agent_id,
    #             source=event.metadata.source,
    #             timestamp=event.metadata.timestamp.ToDatetime(),
    #             expiration=event.metadata.expiration.ToDatetime(),
    #             local_address=i.local_address,
    #             remote_address=i.remote_address,
    #             protocol=i.protocol,
    #             state=i.state,
    #             process_id=i.process_id,
    #             process_name=i.process_name,
    #             service=i.service,
    #         )

    #         await self.db.add_network_connection(data)

    def is_remote_host(self, metadata: pb.Metadata) -> bool:
        """Determines if a message that contains host data is from a remote host.

        Rules:
         1) automated: true + source = Remote
         2) automated: true + No source = Local Data (Data local to the host the agent is running on)
         3) automated: False + source = Local Data (Data local to the host the agent is running on, manually uploaded)
         4) automated: False + No source = Unsupported Error

        Args:
            metadata (pb.Metadata): The metadata of the host data message to check.

        Returns:
            bool: True if the message is contains data about a remote host, False if the message is reporting data about the host the agent is running on.
        """
        if metadata.automated:
            if metadata.HasField("source"):
                if metadata.source.isspace():
                    raise ValueError("Automated message's 'source' field cannot be empty")

                # Rule 1) Automated + Source = Remote host
                return True

            else:
                # Rule 2) Automated + No source = Local Data
                return False
        else:
            if metadata.HasField("source"):
                if metadata.source.isspace():
                    raise ValueError("Manually submitted 'source' field cannot be empty")

                # Rule 3: Not Automated + source = Local Data (manually uploaded)
                return False
            else:
                # Rule 4: Not Automated + No source = Unsupported Error
                raise ValueError("Manually submitted data must have a 'source' field")

    async def add_manual_agent_host(self, metadata: pb.Metadata, project_id: int) -> Tuple[int, int]:
        # If it's manual upload, auto-generate a new a unique agent ID and add host
        new_agent_id = f"{metadata.agent_id}-{uuid.uuid4()}"
        host_mapping_data = HostMappingData.from_str(metadata.source)

        hostagent_row_id, agent_id = await self.db.register_agent_host(
            project_id,
            metadata.timestamp.ToDatetime(),
            metadata.expiration.ToDatetime(),
            new_agent_id,
            metadata.agent_type,
            host_mapping_data.short_name,
            host_mapping_data.long_name,
            host_mapping_data.ip_address,
        )

        return hostagent_row_id, agent_id

    async def add_automated_remote_host(self, metadata: pb.Metadata, project_id: int) -> Tuple[int, int]:
        #   Data is for a remote host. Two things we need to do:
        #     Step 1) Register the current agent + local host
        #     Step 2) Create a new host associated with current agent + remote host

        # Step 1) Register the current agent + local host
        _, agent_id = await self.db.register_agent_host(
            project_id,
            metadata.timestamp.ToDatetime(),
            metadata.expiration.ToDatetime(),
            metadata.agent_id,
            metadata.agent_type,
            None,
            None,
            None,
        )

        # Step 2) Create a new host associated with current agent + remote host
        host_mapping_data = HostMappingData.from_str(metadata.source)
        new_host = await self.db.add_host(
            project_id,
            host_mapping_data.short_name,
            host_mapping_data.long_name,
            host_mapping_data.ip_address,
        )

        return new_host.row_id, agent_id

    async def add_automated_local_host(self, metadata: pb.Metadata, project_id: int) -> Tuple[int, int]:
        # If it's manual, auto-generate a new agent ID and add host
        host_mapping_data = HostMappingData.from_str(metadata.source)

        hostagent_row_id, agent_id = await self.db.register_agent_host(
            project_id,
            metadata.timestamp.ToDatetime(),
            metadata.expiration.ToDatetime(),
            metadata.agent_id,
            metadata.agent_type,
            host_mapping_data.short_name,
            host_mapping_data.long_name,
            host_mapping_data.ip_address,
        )

        return hostagent_row_id, agent_id

    async def register_host(self, metadata: pb.Metadata, project_id: int, is_remote: bool) -> Tuple[int, int]:
        """Registers a host and agent in the database"""

        if metadata.automated:
            if metadata.HasField("source"):
                if metadata.source.isspace():
                    raise ValueError("Automated message's 'source' field cannot be empty")

                return await self.add_automated_remote_host(metadata, project_id)
            else:
                # No source, so it's for the local host
                return await self.add_automated_local_host(metadata, project_id)
        else:
            return await self.add_manual_agent_host(metadata, project_id)

        raise RuntimeError("Should never get here")

    async def register_agent(self, metadata: pb.Metadata, host_mapping_data: Optional[HostMappingData]) -> Agent:
        if host_mapping_data:
            host = await self.db.add_host(
                metadata,
                host_mapping_data.short_name,
                host_mapping_data.long_name,
                host_mapping_data.ip_address,
            )

            agent = await self.db.add_agent(
                metadata,
                host.row_id,
            )

            return agent
        else:
            pass

    @aio.time(Summary("process_named_pipe", "Time spent processing an named_pipe queue"))  # type: ignore
    async def process_named_pipe(self, event: pb.NamedPipeIngestionMessage):
        """Main function to process named_pipe queue."""

        m = event.metadata

        project_id = await self.db.register_project(
            Project(
                m.project,
                m.timestamp.ToDatetime(),
                m.expiration.ToDatetime(),
            )
        )

        is_remote = self.is_remote_host(event.metadata)
        host_row_id, agent_id = await self.register_host(event.metadata, project_id, is_remote)

        for i in event.data:
            data = NamedPipe(
                project_id=project_id,
                collection_timestamp=m.timestamp.ToDatetime(),
                expiration_date=m.expiration.ToDatetime(),
                agent_id=agent_id,
                message_id=uuid.UUID(m.message_id),
                operation=OperationType(m.operation),
                hostagents_row_id=host_row_id,
                is_data_remote=is_remote,
                name=i.name,
                server_process_id=i.server_process_id if i.HasField("server_process_id") else None,
                server_process_name=i.server_process_name if i.HasField("server_process_name") else None,
                server_process_path=i.server_process_path if i.HasField("server_process_path") else None,
                server_process_session_id=i.server_process_session_id if i.HasField("server_process_session_id") else None,
                sddl=i.sddl if i.HasField("sddl") else None,
            )

            await self.db.add_named_pipe(data)

        # @aio.time(Summary("process_network_connection", "Time spent processing an network_connection queue"))  # type: ignore
        # async def process_network_connection(self, event: pb.NetworkConnectionIngestionMessage):
        #     """Main function to process network_connection queue."""

        #     await self.ensure_project_exists(event.metadata)

        #     for i in event.data:
        #         data = NetworkConnection(
        #             project_id=event.metadata.project,
        #             agent_id=event.metadata.agent_id,
        #             source=event.metadata.source,
        #             timestamp=event.metadata.timestamp.ToDatetime(),
        #             expiration=event.metadata.expiration.ToDatetime(),
        #             local_address=i.local_address,
        #             remote_address=i.remote_address,
        #             protocol=i.protocol,
        #             state=i.state,
        #             process_id=i.process_id,
        #             process_name=i.process_name,
        #             service=i.service,
        #         )

        #         await self.db.add_network_connection(data)

        # async def get_tags(self, file: dict[str, Any]):
        #     tags = []
        #     if "contains_dpapi" in file and file["contains_dpapi"]:
        #         tags.append(constants.E_TAG_CONTAINS_DPAPI)
        #     if "noseyparker" in file and file["noseyparker"]:
        #         tags.append(constants.E_TAG_NOSEYPARKER_RESULTS)
        #     if "parsed_data" in file and file["parsed_data"]:
        #         if "has_parsed_credentials" in file["parsed_data"] and file["parsed_data"]["has_parsed_credentials"]:
        #             tags.append(constants.E_TAG_PARSED_CREDS)
        #         if "is_encrypted" in file["parsed_data"] and file["parsed_data"]["is_encrypted"]:
        #             tags.append(constants.E_TAG_ENCRYPTED)
        #     if "analysis" in file and file["analysis"] and "dotnet_analysis" in file["analysis"] and file["analysis"]["dotnet_analysis"]:
        #         if "has_deserialization" in file["analysis"]["dotnet_analysis"] and file["analysis"]["dotnet_analysis"]["has_deserialization"]:
        #             tags.append(constants.E_TAG_DESERIALIZATION)
        #         if "has_cmd_execution" in file["analysis"]["dotnet_analysis"] and file["analysis"]["dotnet_analysis"]["has_cmd_execution"]:
        #             tags.append(constants.E_TAG_CMD_EXECUTION)
        #         if "has_remoting" in file["analysis"]["dotnet_analysis"] and file["analysis"]["dotnet_analysis"]["has_remoting"]:
        #             tags.append(constants.E_TAG_REMOTING)
        #     if "yara_matches" in file and file["yara_matches"]:
        #         for rule in file["yara_matches"]:
        #             if rule not in constants.EXCLUDED_YARA_RULES:
        #                 tags.append(constants.E_TAG_YARA_MATCHES)
        #     if "canaries" in file and file["canaries"] and file["canaries"]["canaries_present"]:
        #         tags.append(constants.E_TAG_FILE_CANARY)

        # return list(set(tags))

    # async def get_tags(self, file: dict[str, Any]):
    #     tags = []
    #     if "contains_dpapi" in file and file["contains_dpapi"]:
    #         tags.append(constants.E_TAG_CONTAINS_DPAPI)
    #     if "noseyparker" in file and file["noseyparker"]:
    #         tags.append(constants.E_TAG_NOSEYPARKER_RESULTS)
    #     if "parsed_data" in file and file["parsed_data"]:
    #         if "has_parsed_credentials" in file["parsed_data"] and file["parsed_data"]["has_parsed_credentials"]:
    #             tags.append(constants.E_TAG_PARSED_CREDS)
    #         if "is_encrypted" in file["parsed_data"] and file["parsed_data"]["is_encrypted"]:
    #             tags.append(constants.E_TAG_ENCRYPTED)
    #     if "analysis" in file and file["analysis"] and "dotnet_analysis" in file["analysis"] and file["analysis"]["dotnet_analysis"]:
    #         if "has_deserialization" in file["analysis"]["dotnet_analysis"] and file["analysis"]["dotnet_analysis"]["has_deserialization"]:
    #             tags.append(constants.E_TAG_DESERIALIZATION)
    #         if "has_cmd_execution" in file["analysis"]["dotnet_analysis"] and file["analysis"]["dotnet_analysis"]["has_cmd_execution"]:
    #             tags.append(constants.E_TAG_CMD_EXECUTION)
    #         if "has_remoting" in file["analysis"]["dotnet_analysis"] and file["analysis"]["dotnet_analysis"]["has_remoting"]:
    #             tags.append(constants.E_TAG_REMOTING)
    #     if "yara_matches" in file and file["yara_matches"]:
    #         for rule in file["yara_matches"]:
    #             if rule not in constants.EXCLUDED_YARA_RULES:
    #                 tags.append(constants.E_TAG_YARA_MATCHES)
    #     if "canaries" in file and file["canaries"] and file["canaries"]["canaries_present"]:
    #         tags.append(constants.E_TAG_FILE_CANARY)

    #     return list(set(tags))
