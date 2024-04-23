# Standard Libraries
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, StrEnum
from types import TracebackType
from typing import AsyncGenerator, List, Optional, Tuple, Type, TypeVar
from uuid import UUID

# 3rd Party Libraries
import asyncpg
import nemesispb.nemesis_pb2 as pb


@dataclass
class ProjectData:
    project_id: str
    timestamp: datetime
    expiration: datetime


class OperationType(StrEnum):
    LIST = "list"
    ADD = "add"
    REMOVE = "remove"


@dataclass
class CollectedData:
    project_id: UUID
    collection_timestamp: datetime
    expiration_date: datetime
    agent_id: UUID
    message_id: UUID
    operation: OperationType


@dataclass
class CollectedHostData(CollectedData):
    hostagents_row_id: UUID
    is_data_remote: bool


@dataclass
class Project:
    project_name: str
    creation_timestamp: datetime
    expiration_date: datetime


@dataclass
class HostAgent:
    row_id: UUID
    shortname: Optional[str]
    longname: Optional[str]
    ip_address: Optional[str]
    project_id: int
    host_id: UUID


@dataclass
class Agent(ProjectData):
    agent_id: str
    type: str
    host_row_id: int


@dataclass
class NamedPipe(CollectedHostData):
    name: str
    server_process_id: Optional[int]
    server_process_name: Optional[str]
    server_process_path: Optional[str]
    server_process_session_id: Optional[int]
    sddl: Optional[str]


@dataclass
class ProcessEnriched(CollectedHostData):
    name: Optional[str]
    command_line: Optional[str]
    file_name: Optional[str]
    process_id: Optional[int]
    parent_process_id: Optional[int]
    arch: Optional[str]
    username: Optional[str]
    category: Optional[str]
    description: Optional[str]


@dataclass
class Metadata:
    agent_id: str
    project_id: str
    timestamp: datetime
    expiration: datetime


# @dataclass
# class NetworkConnection(Metadata):
#     local_address: str = None
#     remote_address: str = None
#     protocol: str = None
#     state: str = None
#     process_id: int = None
#     process_name: str = None
#     service: str = None


# @dataclass
# class ChromiumHistoryEntry(Metadata):
#     user_data_directory: str = None
#     username: str = None
#     browser: str = None
#     url: str = None
#     title: str = None
#     visit_count: int = None
#     typed_count: int = None
#     last_visit_time: datetime = None
#     originating_object_id: UUID4 = None


# @dataclass
# class ChromiumDownload(Metadata):
#     user_data_directory: str = None
#     username: str = None
#     browser: str = None
#     url: str = None
#     download_path: str = None
#     start_time: datetime = None
#     end_time: datetime = None
#     total_bytes: int = None
#     danger_type: str = None
#     originating_object_id: UUID4 = None


# @dataclass
# class ChromiumLogin(Metadata):
#     user_data_directory: str = None
#     username: str = None
#     browser: str = None
#     origin_url: str = None
#     username_value: str = None
#     signon_realm: str = None
#     date_created: datetime = None
#     date_last_used: datetime = None
#     date_password_modified: datetime = None
#     times_used: int = None
#     password_value_enc: bytes = None
#     encryption_type: str = None
#     masterkey_guid: str = None
#     is_decrypted: bool = False
#     password_value_dec: str = None
#     originating_object_id: UUID4 = None


# @dataclass
# class ChromiumCookie(Metadata):
#     user_data_directory: str = None
#     username: str = None
#     browser: str = None
#     host_key: str = None
#     name: str = None
#     path: str = None
#     creation: datetime = None
#     expires: datetime = None
#     last_access: datetime = None
#     last_update: datetime = None
#     is_secure: bool = None
#     is_httponly: bool = None
#     is_session: bool = None
#     samesite: str = None
#     source_port: int = None
#     value_enc: bytes = None
#     encryption_type: str = None
#     masterkey_guid: str = None
#     is_decrypted: bool = False
#     value_dec: str = None
#     originating_object_id: UUID4 = None


# @dataclass
# class ChromiumStateFile(Metadata):
#     user_data_directory: str = None
#     username: str = None
#     browser: str = None
#     installation_date: datetime = None
#     launch_count: int = None
#     masterkey_guid: str = None
#     key_bytes_enc: bytes = None
#     app_bound_fixed_data_enc: bytes = None
#     is_decrypted: bool = False
#     key_bytes_dec: bytes = None
#     app_bound_fixed_data_dec: bytes = None
#     originating_object_id: UUID4 = None


# @dataclass
# class AuthenticationData(Metadata):
#     data: str = None
#     type: str = None
#     is_file: bool = False
#     uri: str = None
#     username: str = None
#     notes: str = None
#     originating_object_id: UUID4 = None


# @dataclass
# class ExtractedHash(Metadata):
#     hash_type: str = None
#     hash_value: str = None
#     originating_object_id: UUID4 = None
#     hashcat_formatted_value: str = None
#     jtr_formatted_value: str = None
#     is_cracked: bool = False
#     checked_against_top_passwords: bool = False
#     plaintext_value: str = None
#     is_submitted_to_cracker: bool = False
#     cracker_submission_time: datetime = None
#     cracker_cracked_time: datetime = None


# @dataclass
# class DpapiBlob(Metadata):
#     dpapi_blob_id: str
#     masterkey_guid: UUID4
#     originating_object_id: UUID4
#     originating_registry_id: UUID4
#     is_file: bool
#     is_decrypted: bool
#     enc_data_bytes: Optional[bytes] = None
#     enc_data_object_id: Optional[UUID4] = None
#     dec_data_bytes: Optional[bytes] = None
#     dec_data_object_id: Optional[UUID4] = None


# @dataclass
# class DpapiMasterkey(Metadata):
#     object_id: str = None
#     type: str = None
#     username: str = None
#     user_sid: str = None
#     masterkey_guid: UUID4 = None
#     is_decrypted: bool = False
#     masterkey_bytes: bytes = None
#     domain_backupkey_guid: Optional[UUID4] = None
#     domainkey_pb_secret: Optional[bytes] = None
#     decrypted_key_full: Optional[bytes] = None
#     decrypted_key_sha1: Optional[bytes] = None


# @dataclass
# class DpapiDomainBackupkey(Metadata):
#     domain_backupkey_guid: str
#     domain_controller: str
#     domain_backupkey_bytes: bytes


# @dataclass
# class Service(Metadata):
#     domain_backupkey_guid: str = None
#     domain_controller: str = None
#     domain_backupkey_bytes: bytes = None


@dataclass
class RegistryObject(Metadata):
    key: str
    value_kind: Optional[int] = None
    sddl: Optional[str] = None
    value_name: Optional[str] = None
    value: Optional[str] = None
    tags: Optional[str] = None


# @dataclass
# class HostInfo(Metadata):
#     hostname: str
#     description: Optional[str] = None
#     os_type: Optional[str] = None
#     windows_major_version: Optional[Decimal] = None
#     windows_build: Optional[str] = None
#     windows_release: Optional[int] = None
#     windows_domain: Optional[str] = None

#     @classmethod
#     def from_seatbelt_dto(cls, dto: SeatbeltOSInfo, m: Metadata) -> Self:
#         """Converts a SeatbeltOSInfo DTO object to a NemesisDB HostInfo object.

#         Args:
#             dto (SeatbeltOSInfo): The SeatbeltOSInfo object to convert
#             metadata (Metadata): The metadata for the raw_data event

#         Returns:
#             HostInfo: The converted HostInfo object
#         """

#         hostname = dto.Hostname
#         description = dto.ProductName
#         os_type = "windows"
#         windows_major_version = dto.CurrentMajorVersionNumber
#         windows_build = dto.Build
#         windows_release = dto.ReleaseId
#         windows_domain = dto.Domain

#         h = HostInfo(
#             m.agent_id,
#             m.project_id,
#             m.source,
#             m.timestamp,
#             m.expiration,
#             hostname,
#             description,
#             os_type,
#             windows_major_version,
#             windows_build,
#             windows_release,
#             windows_domain,
#         )
#         return h


# @dataclass
# class SlackDownload(Metadata):
#     username: str
#     team_id: Optional[str] = None
#     user_id: Optional[str] = None
#     download_path: Optional[str] = None
#     start_time: Optional[datetime] = None
#     workspace_id: Optional[str] = None
#     download_id: Optional[str] = None
#     url: Optional[str] = None
#     download_state: Optional[str] = None
#     end_time: Optional[datetime] = None


# @dataclass
# class SlackWorkspace(Metadata):
#     username: str
#     workspace_name: Optional[str] = None
#     workspace_domain: Optional[str] = None
#     workspace_id: Optional[str] = None
#     workspace_icon_url: Optional[str] = None


# @dataclass
# class FileInfo(Metadata):
#     path: str
#     type: str
#     name: Optional[str] = None
#     extension: Optional[str] = None
#     size: Optional[int] = None
#     access_time: Optional[datetime] = None
#     creation_time: Optional[datetime] = None
#     modification_time: Optional[datetime] = None
#     owner: Optional[str] = None
#     sddl: Optional[str] = None
#     version_info: Optional[str] = None


@dataclass
class FileInfoDataEnriched(CollectedHostData):
    path: str
    name: Optional[str] = None
    extension: Optional[str] = None
    size: Optional[int] = None
    magic_type: Optional[str] = None
    nemesis_file_id: Optional[str] = None


# @dataclass
# class FileDataEnriched(Metadata):
#     object_id: str
#     path: str
#     name: str
#     size: int
#     md5: str
#     sha1: str
#     sha256: str
#     nemesis_file_type: str
#     magic_type: str
#     converted_pdf_id: Optional[str] = None
#     extracted_plaintext_id: Optional[str] = None
#     extracted_source_id: Optional[str] = None
#     originating_object_id: Optional[str] = None
#     tags: Optional[List[str]] = None


class ServiceColumn(Enum):
    BINARY_PATH = "binary_path"
    COMMAND_LINE = "command_line"
    DESCRIPTION = "description"
    DISPLAY_NAME = "display_name"
    SDDL = "sddl"
    SERVICE_DLL_ENTRYPOINT = "service_dll_entrypoint"
    SERVICE_DLL_PATH = "service_dll_path"
    SERVICE_TYPE = "service_type"
    START_TYPE = "start_type"
    USERNAME = "username"


class NemesisDbInterface(ABC):
    @abstractmethod
    async def add_api_data_message(self, message_id: str, message_bytes: bytes) -> None:
        pass

    @abstractmethod
    async def clear_database(self) -> None:
        pass

    @abstractmethod
    async def get_api_data_messages(self) -> AsyncGenerator[bytes, None]:
        pass

    @abstractmethod
    async def register_project(self, project: Project) -> int:
        pass

    @abstractmethod
    async def get_agent(self, agent_id: str) -> Optional[Agent]:
        pass

    @abstractmethod
    async def add_agent(self, metadata: pb.Metadata, host_row_id: int) -> Agent:
        pass

    @abstractmethod
    async def add_host(
        self, project_id: int, shortname: Optional[str], fqdn: Optional[str], ip_address: Optional[str]
    ) -> HostAgent:
        pass

    @abstractmethod
    async def register_agent_host(self, metadata: pb.Metadata, shortname: str, longname: str, ip_address: str) -> int:
        pass

    # @abstractmethod
    # async def add_chromium_history_entry(self, history_entry: ChromiumHistoryEntry) -> None:
    #     pass

    # @abstractmethod
    # async def add_chromium_download(self, download: ChromiumDownload) -> None:
    #     pass

    # @abstractmethod
    # async def add_chromium_login(self, login: ChromiumLogin) -> None:
    #     pass

    # @abstractmethod
    # async def add_chromium_cookie(self, cookie: ChromiumCookie) -> None:
    #     pass

    # @abstractmethod
    # async def add_chromium_state_file(self, state_file: ChromiumStateFile) -> None:
    #     pass

    # @abstractmethod
    # async def add_authentication_data(self, auth_data: AuthenticationData) -> None:
    #     pass

    # @abstractmethod
    # async def add_extracted_hash(self, auth_data: ExtractedHash) -> None:
    #     pass

    # @abstractmethod
    # async def add_dpapi_blob(self, dpapi_blob: DpapiBlob) -> None:
    #     pass

    # @abstractmethod
    # async def add_dpapi_masterkey(self, obj: DpapiMasterkey) -> None:
    #     pass

    # @abstractmethod
    # async def add_dpapi_domain_backupkey(self, obj: DpapiDomainBackupkey) -> None:
    #     pass

    # @abstractmethod
    # async def add_registry_object(self, registry_object: RegistryObject) -> None:
    #     pass

    # @abstractmethod
    # async def add_service(self, metadata: pb.Metadata, service_name: str) -> None:
    #     pass

    # @abstractmethod
    # async def add_service_property(
    #     self,
    #     metadata: pb.Metadata,
    #     service_name: str,
    #     value_name: ServiceColumn,
    #     value: Union[int, str],
    # ) -> None:
    #     pass

    # @abstractmethod
    # async def add_host_info(self, os_info: HostInfo) -> None:
    #     pass

    # @abstractmethod
    # async def add_slack_download(self, slack_download: SlackDownload) -> None:
    #     pass

    # @abstractmethod
    # async def add_slack_workspace(self, slack_workspace: SlackWorkspace) -> None:
    #     pass

    @abstractmethod
    async def add_named_pipe(self, named_pipe: NamedPipe) -> None:
        pass

    # @abstractmethod
    # async def add_network_connection(self, network_connection: NetworkConnection) -> None:
    #     pass

    # @abstractmethod
    # async def add_filesystem_object(self, file_info: FileInfo) -> None:
    #     pass

    @abstractmethod
    async def add_filesystem_object_from_enriched(self, file_data_enriched: FileInfoDataEnriched) -> None:
        pass

    # @abstractmethod
    # async def get_encrypted_dpapi_masterkeys(self, domain_backupkey_guid: str):
    #     pass

    # @abstractmethod
    # async def get_encrypted_dpapi_blobs(self, masterkey_guid: str) -> List[Tuple[uuid.UUID, bool, bytes, uuid.UUID]]:
    #     pass

    # @abstractmethod
    # async def get_decrypted_dpapi_masterkey(self, masterkey_guid: str):
    #     pass

    # @abstractmethod
    # async def get_dpapi_domain_backupkey(self, domain_backupkey_guid: str) -> Optional[bytes]:
    #     pass

    # @abstractmethod
    # async def update_decrypted_dpapi_masterkey(self, masterkey_guid: str, decrypted_key_sha1: bytes, decrypted_key_full: bytes) -> None:
    #     pass

    # @abstractmethod
    # async def update_decrypted_dpapi_blob(
    #     self,
    #     dpapi_blob_id: uuid.UUID,
    #     dec_data_bytes: Optional[bytes],
    #     dec_data_object_id: Optional[UUID],
    # ) -> None:
    #     pass

    # @abstractmethod
    # async def get_decrypted_chromium_state_key(self, source: str, user_data_directory: str):
    #     pass

    # @abstractmethod
    # async def get_encrypted_chromium_state_key(self, masterkey_guid: str) -> List[Tuple[str, str, uuid.UUID, bytes, bytes]]:
    #     pass

    # @abstractmethod
    # async def update_decrypted_chromium_state_key(self, unique_db_id: UUID4, key_bytes_dec: bytes, app_bound_fixed_data_dec: bytes | None) -> None:
    #     pass

    # @abstractmethod
    # async def get_dpapi_encrypted_chromium_logins(self, masterkey_guid: str) -> List[Tuple[uuid.UUID, bytes]]:
    #     pass

    # @abstractmethod
    # async def get_aes_encrypted_chromium_logins(self, source: str, user_data_directory: str) -> List[Tuple[uuid.UUID, bytes]]:
    #     pass

    # @abstractmethod
    # async def update_decrypted_chromium_login(self, unique_db_id: UUID4, password_value_dec: str) -> None:
    #     pass

    # @abstractmethod
    # async def get_dpapi_encrypted_chromium_cookies(self, masterkey_guid: str) -> List[Tuple[uuid.UUID, bytes]]:
    #     pass

    # @abstractmethod
    # async def get_aes_encrypted_chromium_cookies(self, source: str, user_data_directory: str) -> List[Tuple[uuid.UUID, bytes]]:
    #     pass

    # @abstractmethod
    # async def update_decrypted_chromium_cookie(self, unique_db_id: UUID4, value_dec: str) -> None:
    #     pass

    # @abstractmethod
    # async def is_file_processed(self, file_sha256: str) -> bool:
    #     pass


NemesisDbT = TypeVar("NemesisDbT", bound="NemesisDb")
_Record = TypeVar("_Record", bound=asyncpg.protocol.Record)
_R = TypeVar("_R", bound=asyncpg.Record)


class NemesisDb(NemesisDbInterface):
    """
    Generic database interface for Nemesis data types
    """

    pool: asyncpg.pool.Pool

    def __init__(self, pool: asyncpg.pool.Pool):
        if not pool:
            raise Exception("Invalid connection pool")
        self.pool = pool

    @staticmethod
    async def create(connection_uri: str):
        pool = await asyncpg.create_pool(dsn=connection_uri)
        if not pool:
            raise Exception("Failed to create connection pool")
        return NemesisDb(pool)

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        await self.Close()

    async def Close(self) -> None:
        await self.pool.close()

    #
    # Functions that help with reprocessing
    #

    async def add_api_data_message(self, message_id: str, message_bytes: bytes, expiration: datetime) -> None:
        """Adds a new `nemesis.api_data_message` entry to the database."""

        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO nemesis.api_data_messages (message_id, message_bytes, expiration) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                message_id,
                message_bytes,
                expiration,
            )

    async def clear_database(self) -> None:
        """Clears all tables in the database except for the `nemesis.api_data_messages` table."""

        async with self.pool.acquire() as conn:
            table_names = await conn.fetch(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'nemesis' AND table_name != 'api_data_messages'",
            )
            for table_name in table_names:
                await conn.execute(f"TRUNCATE TABLE nemesis.{table_name[0]} CASCADE")

    async def expunge_expirated_data(self) -> None:
        """Clears data from all tables where the `expiration` has now passed."""
        async with self.pool.acquire() as conn:
            table_names = await conn.fetch(
                "SELECT table_name FROM information_schema.columns WHERE column_name = 'expiration'",
            )
            for table_name_result in table_names:
                table_name = table_name_result["table_name"]
                # the DB timezone is already set to UTC in the schema
                await conn.execute(f"DELETE FROM nemesis.{table_name} WHERE expiration <= NOW()")

    async def get_api_data_messages(self) -> AsyncGenerator[bytes, None]:
        """Returns the raw bytes for all POST /data messages."""

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                async for message_bytes in conn.cursor("SELECT message_bytes FROM nemesis.api_data_messages"):
                    yield message_bytes[0]

    #
    # Other
    #

    async def register_project(self, project: Project) -> UUID:
        """Registers a project in the database and returnts the id. If the project already exists, the id is returned."""

        async with self.pool.acquire() as conn:
            query = """
SELECT f_register_project($1, $2, $3)
"""
            results = await conn.fetchrow(
                query,
                project.project_name,
                project.creation_timestamp,
                project.expiration_date,
            )
            if not results:
                raise RuntimeError("Failed to add project to database: null result returned")

            return results[0]

    async def get_agent(self, agent_id: str) -> Optional[Agent]:
        async with self.pool.acquire() as conn:
            query = """
SELECT project_id, timestamp, expiration, agent_id, type, host_row_id
FROM agents
WHERE agent_id = $1
"""
            results = await conn.fetchrow(query, agent_id)

            if not results:
                return None

            return Agent(*results)

    async def add_agent(self, metadata: pb.Metadata, host_row_id: int) -> Agent:
        """Adds a new `nemesis.hosts` entry ."""

        query = """
INSERT INTO agents (
    project_id,
    timestamp,
    expiration,
    agent_id,
    type,
    host_row_id
)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT DO NOTHING
RETURNING *
"""

        async with self.pool.acquire() as conn:
            results = await conn.fetchrow(
                query,
                metadata.project,
                metadata.timestamp.ToDatetime(),
                metadata.expiration.ToDatetime(),
                metadata.agent_id,
                metadata.agent_type,
                host_row_id,
            )

        if not results:
            raise RuntimeError("Failed to add agent to database: null result returned")

        return Agent(*results)

    async def add_host(
        self, project_id: UUID, shortname: Optional[str], fqdn: Optional[str], ip_address: Optional[str]
    ) -> HostAgent:
        """Adds a new `nemesis.agent_host_mappings` entry ."""

        query = """
INSERT INTO agent_host_mappings (shortname, longname, ip_address, project_id)
VALUES ($1, $2, $3, $4)
RETURNING *
"""
        async with self.pool.acquire() as conn:
            results = await conn.fetchrow(
                query,
                shortname,
                fqdn,
                ip_address,
                project_id,
            )

        if not results:
            raise RuntimeError("Failed to add host to database: null result returned")

        return HostAgent(*results)

    async def register_agent_host(
        self,
        project_id: UUID,
        collection_timestamp: datetime,
        expiration_date: datetime,
        agent_id: str,
        agent_type: str,
        shortname: Optional[str],
        longname: Optional[str],
        ip_address: Optional[str],
    ) -> Tuple[UUID, UUID]:
        """Registers a host in the database and returns the hostagents_row_id and the new agent_id. If the host already exists, the hostagents_row_id and the existing agent_id are returned.

        Args:
            project_id (int): Project ID associated with the data
            collection_timestamp (datetime): When the data was collected
            expiration_date (datetime): When the data expires
            agent_id (str): String ID of the agent
            agent_type (str): String identifying the type of agent (e.g., beacon, apollo, sliver, etc.)
            shortname (Optional[str]): Optional short name of the host (e.g., NetBIOS name)
            longname (Optional[str]): Optional long name of the host (e.g., fully qualified domain name)
            ip_address (Optional[str]): Optional IP address of the host that an agent returns. This may expand in the future to support multiple adapters.

        Returns:
            Tuple[int, int]: Returns a tuple containing the hostagents_row_id and the agent_id
        """
        query = """
SELECT f_register_agent_host($1, $2, $3, $4, $5, $6, $7, $8)
"""
        async with self.pool.acquire() as conn:
            try:
                results = await conn.fetchrow(
                    query,
                    project_id,
                    collection_timestamp,
                    expiration_date,
                    agent_id,
                    agent_type,
                    shortname,
                    longname,
                    ip_address,
                )
            except asyncpg.UniqueViolationError:
                # Need for a potential concurrency error:
                # When an agent doesn't already exist, there's a chance by the end of this transaction
                # that a separate transation may have already added the agent. As such, a UniqueViolationError
                # may occur. This could be solved in the SQL function's INSERT statement using https://stackoverflow.com/a/42217872,
                # but it'll happen so rarely that it's not worth the effort right now.
                results = await conn.fetchrow(
                    query,
                    project_id,
                    collection_timestamp,
                    expiration_date,
                    agent_id,
                    agent_type,
                    shortname,
                    longname,
                    ip_address,
                )

        if not results:
            raise RuntimeError("Failed to add host to database: null result returned")

        if len(results[0]) != 2:
            raise RuntimeError("Failed to add host to database: unexpected result returned")

        hostagent_row_id = results[0][0]
        new_agent_id = results[0][1]

        return hostagent_row_id, new_agent_id

    # async def add_chromium_history_entry(self, history_entry: ChromiumHistoryEntry) -> None:
    #     """Adds a new `nemesis.chromium_history` entry from a ChromiumHistoryEntry class object."""

    #     query = (
    #         "INSERT INTO nemesis.chromium_history (agent_id, project_id, source, timestamp, expiration, originating_object_id, user_data_directory, username, browser, url, title, visit_count, typed_count, last_visit_time) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             history_entry.agent_id,
    #             history_entry.project_id,
    #             history_entry.source,
    #             history_entry.timestamp,
    #             history_entry.expiration,
    #             history_entry.originating_object_id,
    #             history_entry.user_data_directory,
    #             history_entry.username,
    #             history_entry.browser,
    #             history_entry.url,
    #             history_entry.title,
    #             history_entry.visit_count,
    #             history_entry.typed_count,
    #             history_entry.last_visit_time,
    #         )

    # async def add_chromium_download(self, download: ChromiumDownload) -> None:
    #     """Adds a new `nemesis.chromium_downloads` entry from a ChromiumDownload class object."""

    #     query = (
    #         "INSERT INTO nemesis.chromium_downloads (agent_id, project_id, source, timestamp, expiration, originating_object_id, user_data_directory, username, browser, url, download_path, start_time, end_time, total_bytes, danger_type) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             download.agent_id,
    #             download.project_id,
    #             download.source,
    #             download.timestamp,
    #             download.expiration,
    #             download.originating_object_id,
    #             download.user_data_directory,
    #             download.username,
    #             download.browser,
    #             download.url,
    #             download.download_path,
    #             download.start_time,
    #             download.end_time,
    #             download.total_bytes,
    #             download.danger_type,
    #         )

    # async def add_chromium_login(self, login: ChromiumLogin) -> None:
    #     """Adds a new `nemesis.chromium_logins` entry from a ChromiumLogin class object."""

    #     query = (
    #         "INSERT INTO nemesis.chromium_logins (agent_id, project_id, source, timestamp, expiration, originating_object_id, user_data_directory, username, browser, origin_url, username_value, password_value_enc, signon_realm, date_created, date_last_used, date_password_modified, times_used, encryption_type, masterkey_guid, is_decrypted, password_value_dec) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21) ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             login.agent_id,
    #             login.project_id,
    #             login.source,
    #             login.timestamp,
    #             login.expiration,
    #             login.originating_object_id,
    #             login.user_data_directory,
    #             login.username,
    #             login.browser,
    #             login.origin_url,
    #             login.username_value,
    #             login.password_value_enc,
    #             login.signon_realm,
    #             login.date_created,
    #             login.date_last_used,
    #             login.date_password_modified,
    #             login.times_used,
    #             login.encryption_type,
    #             login.masterkey_guid,
    #             login.is_decrypted,
    #             login.password_value_dec,
    #         )

    # async def add_chromium_cookie(self, cookie: ChromiumCookie) -> None:
    #     """Adds a new `nemesis.chromium_cookies` entry from a ChromiumCookie class object."""

    #     query = (
    #         "INSERT INTO nemesis.chromium_cookies (agent_id, project_id, source, timestamp, expiration, originating_object_id, user_data_directory, username, browser, host_key, name, path, creation_utc, expires_utc, last_access_utc, last_update_utc, is_secure, is_httponly, is_session, samesite, source_port, value_enc, encryption_type, masterkey_guid, is_decrypted, value_dec) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26) ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             cookie.agent_id,
    #             cookie.project_id,
    #             cookie.source,
    #             cookie.timestamp,
    #             cookie.expiration,
    #             cookie.originating_object_id,
    #             cookie.user_data_directory,
    #             cookie.username,
    #             cookie.browser,
    #             cookie.host_key,
    #             cookie.name,
    #             cookie.path,
    #             cookie.creation,
    #             cookie.expires,
    #             cookie.last_access,
    #             cookie.last_update,
    #             cookie.is_secure,
    #             cookie.is_httponly,
    #             cookie.is_session,
    #             cookie.samesite,
    #             cookie.source_port,
    #             cookie.value_enc,
    #             cookie.encryption_type,
    #             cookie.masterkey_guid,
    #             cookie.is_decrypted,
    #             cookie.value_dec,
    #         )

    # async def add_chromium_state_file(self, state_file: ChromiumStateFile) -> None:
    #     """Adds a new `nemesis.chromium_state_files` entry from a ChromiumDownload class object."""

    #     query = (
    #         "INSERT INTO nemesis.chromium_state_files (agent_id, project_id, source, timestamp, expiration, originating_object_id, user_data_directory, username, browser, installation_date, launch_count, masterkey_guid, key_bytes_enc, app_bound_fixed_data_enc, is_decrypted, key_bytes_dec, app_bound_fixed_data_dec) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             state_file.agent_id,
    #             state_file.project_id,
    #             state_file.source,
    #             state_file.timestamp,
    #             state_file.expiration,
    #             state_file.originating_object_id,
    #             state_file.user_data_directory,
    #             state_file.username,
    #             state_file.browser,
    #             state_file.installation_date,
    #             state_file.launch_count,
    #             state_file.masterkey_guid,
    #             state_file.key_bytes_enc,
    #             state_file.app_bound_fixed_data_enc,
    #             state_file.is_decrypted,
    #             state_file.key_bytes_dec,
    #             state_file.app_bound_fixed_data_dec,
    #         )

    # async def add_authentication_data(self, auth_data: AuthenticationData) -> None:
    #     """Adds a new `nemesis.dpapi_blobs` entry from a AuthenticationData class object."""

    #     query = (
    #         "INSERT INTO nemesis.authentication_data ("
    #         "agent_id, project_id, source, timestamp, "
    #         "expiration, data, type, is_file, notes, uri,"
    #         "username, originating_object_id) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             auth_data.agent_id,
    #             auth_data.project_id,
    #             auth_data.source,
    #             auth_data.timestamp,
    #             auth_data.expiration,
    #             auth_data.data,
    #             auth_data.type,
    #             auth_data.is_file,
    #             auth_data.notes,
    #             auth_data.uri,
    #             auth_data.username,
    #             auth_data.originating_object_id,
    #         )

    # async def add_extracted_hash(self, auth_data: ExtractedHash) -> None:
    #     """Adds a new `nemesis.extracted_hashes` entry from a ExtractedHash class object."""

    #     query = (
    #         "INSERT INTO nemesis.extracted_hashes (agent_id, project_id, source, timestamp, expiration, originating_object_id, hash_type, hash_value, jtr_formatted_value, is_cracked, checked_against_top_passwords, plaintext_value) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             auth_data.agent_id,
    #             auth_data.project_id,
    #             auth_data.source,
    #             auth_data.timestamp,
    #             auth_data.expiration,
    #             auth_data.originating_object_id,
    #             auth_data.hash_type,
    #             auth_data.hash_value,
    #             auth_data.jtr_formatted_value,
    #             auth_data.is_cracked,
    #             auth_data.checked_against_top_passwords,
    #             auth_data.plaintext_value,
    #         )

    # if auth_data.is_cracked:
    #     # update any values in the table where the hash matches this cracked value
    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             """
    #             UPDATE nemesis.extracted_hashes
    #             SET is_cracked = True, plaintext_value = $1
    #             WHERE is_cracked= False AND hash_value = $2
    #             """,
    #             auth_data.plaintext_value,
    #             auth_data.hash_value
    #         )

    # async def add_dpapi_blob(self, dpapi_blob: DpapiBlob) -> None:
    #     """Adds a new `nemesis.dpapi_blobs` entry from a DpapiBlob class object."""

    #     query = (
    #         "INSERT INTO nemesis.dpapi_blobs ("
    #         "    agent_id, project_id, source, timestamp, expiration, dpapi_blob_id, originating_object_id, originating_registry_id, masterkey_guid, is_file, is_decrypted, enc_data_bytes, enc_data_object_id, dec_data_bytes, dec_data_object_id) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             dpapi_blob.agent_id,
    #             dpapi_blob.project_id,
    #             dpapi_blob.source,
    #             dpapi_blob.timestamp,
    #             dpapi_blob.expiration,
    #             dpapi_blob.dpapi_blob_id,
    #             dpapi_blob.originating_object_id,
    #             dpapi_blob.originating_registry_id,
    #             dpapi_blob.masterkey_guid,
    #             dpapi_blob.is_file,
    #             dpapi_blob.is_decrypted,
    #             dpapi_blob.enc_data_bytes,
    #             dpapi_blob.enc_data_object_id,
    #             dpapi_blob.dec_data_bytes,
    #             dpapi_blob.dec_data_object_id,
    #         )

    # async def add_dpapi_masterkey(self, obj: DpapiMasterkey) -> None:
    #     """Adds a new `nemesis.dpapi_masterkeys` entry from a DpapiMasterkey class object."""

    #     query = (
    #         "INSERT INTO nemesis.dpapi_masterkeys ( "
    #         "    agent_id, project_id, source, timestamp, expiration, object_id, type, username, user_sid, masterkey_guid, is_decrypted, "
    #         "    masterkey_bytes, domain_backupkey_guid, domainkey_pb_secret, decrypted_key_full, decrypted_key_sha1) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             obj.agent_id,
    #             obj.project_id,
    #             obj.source,
    #             obj.timestamp,
    #             obj.expiration,
    #             obj.object_id,
    #             obj.type,
    #             obj.username,
    #             obj.user_sid,
    #             obj.masterkey_guid,
    #             obj.is_decrypted,
    #             obj.masterkey_bytes,
    #             obj.domain_backupkey_guid,
    #             obj.domainkey_pb_secret,
    #             obj.decrypted_key_full,
    #             obj.decrypted_key_sha1,
    #         )

    # async def add_dpapi_domain_backupkey(self, obj: DpapiDomainBackupkey) -> None:
    #     """Adds a new `nemesis.dpapi_domain_backupkeys` entry from a DpapiDomainBackupkey class object."""

    #     query = (
    #         "INSERT INTO nemesis.dpapi_domain_backupkeys (project_id, agent_id, source, timestamp, expiration, domain_backupkey_guid, domain_controller, domain_backupkey_bytes) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             obj.project_id,
    #             obj.agent_id,
    #             obj.source,
    #             obj.timestamp,
    #             obj.expiration,
    #             obj.domain_backupkey_guid,
    #             obj.domain_controller,
    #             obj.domain_backupkey_bytes,
    #         )

    # async def add_registry_object(self, registry_object: RegistryObject) -> str:
    #     """Adds a new `nemesis.registry_objects` entry from a RegistryObject class object."""

    #     query = (
    #         "INSERT INTO nemesis.registry_objects (agent_id, project_id, source, timestamp, expiration, key, value_name, sddl, value_kind, value, tags) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) "
    #         "ON CONFLICT (project_id, source, key, value_name) DO NOTHING "
    #         "RETURNING unique_db_id"
    #     )

    #     async with self.pool.acquire() as conn:
    #         result = await conn.fetchval(
    #             query,
    #             registry_object.agent_id,
    #             registry_object.project_id,
    #             registry_object.source,
    #             registry_object.timestamp,
    #             registry_object.expiration,
    #             registry_object.key,
    #             registry_object.value_name,
    #             registry_object.sddl,
    #             registry_object.value_kind,
    #             registry_object.value,
    #             registry_object.tags,
    #         )
    #         if result:
    #             return f"{result}"
    #         else:
    #             return ""

    # async def add_service(self, metadata: pb.Metadata, service_name: str) -> None:
    #     """Adds a service to the database

    #     Args:
    #         metadata (pb.Metadata): Metadata for the service object
    #         service_name (str): Name of the service
    #     """

    #     agent_id = metadata.agent_id
    #     project_id = metadata.project
    #     source = metadata.source
    #     timestamp = metadata.timestamp.ToDatetime()
    #     expiration = metadata.expiration.ToDatetime()

    #     query = "INSERT INTO nemesis.services (agent_id, project_id, source, timestamp, expiration, name) " "VALUES ($1, $2, $3, $4, $5, $6) " "ON CONFLICT (project_id, source, name) " "DO UPDATE SET name = $6"

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(query, agent_id, project_id, source, timestamp, expiration, service_name)

    # async def add_service_property(
    #     self,
    #     metadata: pb.Metadata,
    #     service_name: str,
    #     value_name: ServiceColumn,
    #     value: Union[int, str],
    # ) -> None:
    #     """Sets a specific property for a service in the database.

    #     Args:
    #         metadata (pb.Metadata): Metadata for the service object
    #         service_name (str): Name of the service
    #         value_name (ServiceColumn): Name of the property to set. The should NEVER be a user-supplied value.
    #         value (_type_): Value of the property to set
    #     """

    #     agent_id = metadata.agent_id
    #     project_id = metadata.project
    #     source = metadata.source
    #     timestamp = metadata.timestamp.ToDatetime()
    #     expiration = metadata.expiration.ToDatetime()

    #     if value_name in [ServiceColumn.START_TYPE, ServiceColumn.SERVICE_TYPE]:
    #         value_expression = "$7::SMALLINT"
    #     else:
    #         value_expression = "$7"

    #     query = (
    #         f"INSERT INTO nemesis.services (agent_id, project_id, source, timestamp, expiration, name, {value_name.value}) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7) "
    #         f"ON CONFLICT (project_id, source, name) "
    #         f"DO UPDATE SET {value_name.value} = {value_expression}"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             agent_id,
    #             project_id,
    #             source,
    #             timestamp,
    #             expiration,
    #             service_name,
    #             value,
    #         )

    # async def add_host_info(self, os_info: HostInfo) -> None:
    #     """Adds host information to the database, updating only if the existing value is null."""

    #     # TODO: should the description COALESCE be the excluded value first?
    #     query = (
    #         "INSERT INTO nemesis.hosts as t(agent_ids, project_id, source, timestamp, expiration, hostname, description, os_type, windows_major_version, windows_build, windows_release, windows_domain) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) "
    #         "ON CONFLICT (hostname) "
    #         "DO UPDATE SET "
    #         "  description = COALESCE(excluded.description, t.description),"
    #         "  os_type = COALESCE(t.os_type, excluded.os_type),"
    #         "  windows_major_version = COALESCE(t.windows_major_version,excluded.windows_major_version),"
    #         "  windows_build = COALESCE(t.windows_build, excluded.windows_build),"
    #         "  windows_release = COALESCE(t.windows_release, excluded.windows_release), "
    #         "  windows_domain = COALESCE(t.windows_domain, excluded.windows_domain)"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             [os_info.agent_id],
    #             os_info.project_id,
    #             os_info.source,
    #             os_info.timestamp,
    #             os_info.expiration,
    #             os_info.hostname,
    #             os_info.description,
    #             os_info.os_type,
    #             os_info.windows_major_version,
    #             os_info.windows_build,
    #             os_info.windows_release,
    #             os_info.windows_domain,
    #         )

    # async def add_slack_workspace(self, slack_workspace: SlackWorkspace) -> None:
    #     """Adds a new `nemesis.slack_workspace` entry from a SlackWorkspace class object."""

    #     query = (
    #         "INSERT INTO nemesis.slack_workspaces as t(agent_id, project_id, source, timestamp, expiration, username, workspace_id, workspace_domain, workspace_name, workspace_icon_url) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) "
    #         " ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             slack_workspace.agent_id,
    #             slack_workspace.project_id,
    #             slack_workspace.source,
    #             slack_workspace.timestamp,
    #             slack_workspace.expiration,
    #             slack_workspace.username,
    #             slack_workspace.workspace_id,
    #             slack_workspace.workspace_domain,
    #             slack_workspace.workspace_name,
    #             slack_workspace.workspace_icon_url,
    #         )

    # async def add_slack_download(self, slack_download: SlackDownload) -> None:
    #     """Adds a new `nemesis.slack_download` entry from a SlackDownload class object."""

    #     query = (
    #         "INSERT INTO nemesis.slack_downloads as t(agent_id, project_id, source, timestamp, expiration, username, workspace_id, download_id, team_id, user_id, url, download_path, download_state, start_time, end_time) "
    #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) "
    #         " ON CONFLICT DO NOTHING"
    #     )

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(
    #             query,
    #             slack_download.agent_id,
    #             slack_download.project_id,
    #             slack_download.source,
    #             slack_download.timestamp,
    #             slack_download.expiration,
    #             slack_download.username,
    #             slack_download.workspace_id,
    #             slack_download.download_id,
    #             slack_download.team_id,
    #             slack_download.user_id,
    #             slack_download.url,
    #             slack_download.download_path,
    #             slack_download.download_state,
    #             slack_download.start_time,
    #             slack_download.end_time,
    #         )

    async def add_named_pipe(self, named_pipe: NamedPipe) -> None:
        """Adds a new `nemesis.named_pipes` entry from a NamedPipe class object."""

        query = """
INSERT INTO nemesis.hostdata_namedpipes as t(
    project_id,
    collection_timestamp,
    expiration_date,
    agent_id,
    message_id,
    operation,
    hostagents_row_id,
    is_data_remote,
    name,
    server_process_id,
    server_process_name,
    server_process_path,
    server_process_session_id,
    sddl
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
"""

        async with self.pool.acquire() as conn:
            await conn.execute(
                query,
                # ProjectData
                named_pipe.project_id,
                named_pipe.collection_timestamp,
                named_pipe.expiration_date,
                # HostData
                named_pipe.agent_id,
                named_pipe.message_id,
                named_pipe.operation,
                named_pipe.hostagents_row_id,
                named_pipe.is_data_remote,
                # Named Pipe Data
                named_pipe.name,
                named_pipe.server_process_id,
                named_pipe.server_process_name,
                named_pipe.server_process_path,
                named_pipe.server_process_session_id,
                named_pipe.sddl,
            )

    async def add_process(self, process: ProcessEnriched) -> None:
        """Adds a new `nemesis.hostdata_processes` entry from a ProcessEnriched class object."""

        query = """
INSERT INTO nemesis.hostdata_processes as t(
    project_id,
    collection_timestamp,
    expiration_date,
    agent_id,
    message_id,
    operation,
    hostagents_row_id,
    is_data_remote,
    name,
    command_line,
    file_name,
    process_id,
    parent_process_id,
    arch,
    username,
    category,
    description
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
"""
        async with self.pool.acquire() as conn:
            await conn.execute(
                query,
                # ProjectData
                process.project_id,
                process.collection_timestamp,
                process.expiration_date,
                # HostData
                process.agent_id,
                process.message_id,
                process.operation,
                process.hostagents_row_id,
                process.is_data_remote,
                # Process Data
                process.name,
                process.command_line,
                process.file_name,
                process.process_id,
                process.parent_process_id,
                process.arch,
                process.username,
                process.category,
                process.description,
            )

        # async def add_network_connection(self, network_connection: NetworkConnection) -> None:
        #     """Adds a new `nemesis.network_connections` entry from a NetworkConnection class object."""

        #     query = (
        #         "INSERT INTO nemesis.network_connections as t(agent_id, project_id, source, timestamp, expiration, local_address, remote_address, protocol, state, process_id, process_name, service) "
        #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) "
        #     )

        #     async with self.pool.acquire() as conn:
        #         await conn.execute(
        #             query,
        #             network_connection.agent_id,
        #             network_connection.project_id,
        #             network_connection.source,
        #             network_connection.timestamp,
        #             network_connection.expiration,
        #             network_connection.local_address,
        #             network_connection.remote_address,
        #             network_connection.protocol,
        #             network_connection.state,
        #             network_connection.process_id,
        #             network_connection.process_name,
        #             network_connection.service,
        #         )

        # async def add_filesystem_object(self, file_info: FileInfo) -> None:
        #     """Adds a new `nemesis.filesystem_objects` entry from a FileInfo class object."""

        #     # NOTE: size, access_time, creation_time, modification_time, and SDDL are the first in
        #     #   COALESCE to ensure we update the accurate most recent value
        #     query = (
        #         "INSERT INTO nemesis.filesystem_objects as t(agent_id, project_id, source, timestamp, expiration, path, name, extension, type, size, access_time, creation_time, modification_time, owner, sddl) "
        #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) "
        #         "ON CONFLICT (project_id, source, path) "
        #         "DO UPDATE SET "
        #         "  name = COALESCE(t.name, excluded.name),"
        #         "  extension = COALESCE(t.extension, excluded.extension),"
        #         "  type = COALESCE(t.type, excluded.type),"
        #         "  size = COALESCE(excluded.size, t.size),"
        #         "  access_time = COALESCE(excluded.access_time, t.access_time),"
        #         "  creation_time = COALESCE(excluded.creation_time, t.creation_time),"
        #         "  modification_time = COALESCE(excluded.modification_time, t.modification_time),"
        #         "  sddl = COALESCE(excluded.sddl, t.sddl)"
        #     )

        #     async with self.pool.acquire() as conn:
        #         await conn.execute(
        #             query,
        #             file_info.agent_id,
        #             file_info.project_id,
        #             file_info.source,
        #             file_info.timestamp,
        #             file_info.expiration,
        #             file_info.path,
        #             file_info.name,
        #             file_info.extension,
        #             file_info.type,
        #             file_info.size,
        #             file_info.access_time,
        #             file_info.creation_time,
        #             file_info.modification_time,
        #             file_info.owner,
        #             file_info.sddl,
        #         )

    async def add_filesystem_object_from_enriched(self, file_data_enriched: FileInfoDataEnriched) -> None:
        """Adds a new `nemesis.filesystem_objects` entry from a FileInfoDataEnriched class object."""

        # NOTE: size, magic_type, nemesis_file_id are the first in
        #   COALESCE to ensure we update the accurate most recent value
        query = """
INSERT INTO nemesis.hostdata_filesystem_objects as t(
        project_id,
        collection_timestamp,
        expiration_date,
        agent_id,
        message_id,
        operation,
        hostagents_row_id,
        is_data_remote,
        path,
        name,
        extension,
        type,
        size,
        magic_type,
        nemesis_file_id
    )
    VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
    )
"""
        async with self.pool.acquire() as conn:
            await conn.execute(
                query,
                # ProjectData
                file_data_enriched.project_id,
                file_data_enriched.collection_timestamp,
                file_data_enriched.expiration_date,
                # HostData
                file_data_enriched.agent_id,
                file_data_enriched.message_id,
                file_data_enriched.operation,
                file_data_enriched.hostagents_row_id,
                file_data_enriched.is_data_remote,
                # Named Pipe Data
                file_data_enriched.path,
                file_data_enriched.name,
                file_data_enriched.extension,
                "file",
                file_data_enriched.size,
                file_data_enriched.magic_type,
                file_data_enriched.nemesis_file_id,
            )

        # async def add_file_data_enriched(self, file_data_enriched: FileDataEnriched) -> None:
        #     """Adds a new `nemesis.file_data_enriched` entry from a FileDataEnriched class object."""

        #     query = (
        #         "INSERT INTO nemesis.file_data_enriched as t(agent_id, project_id, source, timestamp, expiration, object_id, originating_object_id, path, name, size, md5, sha1, sha256, nemesis_file_type, magic_type, converted_pdf_id, extracted_plaintext_id, extracted_source_id, tags) "
        #         "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) "
        #         " ON CONFLICT DO NOTHING"
        #     )

        #     async with self.pool.acquire() as conn:
        #         await conn.execute(
        #             query,
        #             file_data_enriched.agent_id,
        #             file_data_enriched.project_id,
        #             file_data_enriched.source,
        #             file_data_enriched.timestamp,
        #             file_data_enriched.expiration,
        #             file_data_enriched.object_id,
        #             file_data_enriched.originating_object_id,
        #             file_data_enriched.path,
        #             file_data_enriched.name,
        #             file_data_enriched.size,
        #             file_data_enriched.md5,
        #             file_data_enriched.sha1,
        #             file_data_enriched.sha256,
        #             file_data_enriched.nemesis_file_type,
        #             file_data_enriched.magic_type,
        #             file_data_enriched.converted_pdf_id,
        #             file_data_enriched.extracted_plaintext_id,
        #             file_data_enriched.extracted_source_id,
        #             file_data_enriched.tags,
        #         )

    # async def get_plaintext_passwords(self, username: str = "%"):
    #     """
    #     Returns entries from `authentication_data` where type=password, optionally
    #     filtered by username.
    #     """

    #     async with self.pool.acquire() as conn:
    #         results = await conn.fetch(
    #             "SELECT data FROM nemesis.authentication_data WHERE type = 'password' AND username ILIKE $1",
    #             username,
    #         )
    #         return [result[0] for result in results]

    # async def get_ntlm_hashes(self, username: str = "%"):
    #     """
    #     Returns entries from `authentication_data` where type=ntlm_hash, optionally
    #     filtered by username.
    #     """

    #     async with self.pool.acquire() as conn:
    #         results = await conn.fetch(
    #             "SELECT data FROM nemesis.authentication_data WHERE type = 'ntlm_hash' AND username ILIKE $1",
    #             username,
    #         )
    #     return [result[0] for result in results]

    # async def get_cracked_passwords(self, username: str = "%"):
    #     """Returns entries from `extracted_hashes` where is_cracked=True."""

    #     async with self.pool.acquire() as conn:
    #         results = await conn.fetch(
    #             "SELECT plaintext_value FROM nemesis.extracted_hashes WHERE is_cracked = True AND username ILIKE $1",
    #             username,
    #         )
    #         return [result[0] for result in results]

    # async def get_cracked_hash_value(self, hash_value: str):
    #     """Returns the plaintext value for a hash if it's already cracked."""

    #     async with self.pool.acquire() as conn:
    #         results = await conn.fetch(
    #             "SELECT plaintext_value FROM nemesis.extracted_hashes WHERE is_cracked = True AND hash_value = $1",
    #             hash_value,
    #         )
    #         if results:
    #             return results[0][0]
    #         else:
    #             return None

    async def get_encrypted_dpapi_masterkeys(self, username: str = "%", machine: bool = False):
        """Gets encrypted DPAPI masterkeys linked to a specific domain backupkey guid.

        #     machine -> only return machine masterkeys

        #     TODO: Use cursors to handle lots of results https://magicstack.github.io/asyncpg/current/api/index.html?highlight=fetchval#cursors
        #"""
        if machine:
            query = (
                "SELECT username, user_sid, masterkey_guid, masterkey_bytes FROM nemesis.dpapi_masterkeys WHERE username = $1 AND is_decrypted = False AND type = 'machine'",
            )
        else:
            query = "SELECT username, user_sid, masterkey_guid, masterkey_bytes FROM nemesis.dpapi_masterkeys WHERE username = $1 AND is_decrypted = False AND type != 'machine'"

        async with self.pool.acquire() as conn:
            return await conn.fetch(
                query,
                username,
            )

    async def get_encrypted_dpapi_masterkeys_from_backup_guid(
        self, domain_backupkey_guid: str
    ) -> List[Tuple[uuid.UUID, bytes]]:
        """Gets encrypted DPAPI masterkeys linked to a specific domain backupkey guid.

        TODO: Use cursors to handle lots of results https://magicstack.github.io/asyncpg/current/api/index.html?highlight=fetchval#cursors
        """
        async with self.pool.acquire() as conn:
            return await conn.fetch(
                "SELECT masterkey_guid, domainkey_pb_secret FROM nemesis.dpapi_masterkeys WHERE domain_backupkey_guid = $1 AND is_decrypted = False",
                domain_backupkey_guid,
            )

    async def get_encrypted_dpapi_masterkeys_from_username(self, username: str) -> List[Tuple[uuid.UUID, str, bytes]]:
        """Gets encrypted DPAPI masterkeys linked to a specific username.

        TODO: Use cursors to handle lots of results https://magicstack.github.io/asyncpg/current/api/index.html?highlight=fetchval#cursors
        """
        async with self.pool.acquire() as conn:
            return await conn.fetch(
                "SELECT masterkey_guid, user_sid, masterkey_bytes FROM nemesis.dpapi_masterkeys WHERE username ILIKE $1 AND is_decrypted = False",
                username,
            )

    # async def get_encrypted_dpapi_blobs(self, masterkey_guid: str) -> List[Tuple[uuid.UUID, bool, bytes, uuid.UUID]]:
    #     """Gets encrypted DPAPI blobs linked to a specific masterkey guid.

    #     TODO: Use cursors to handle lots of results https://magicstack.github.io/asyncpg/current/api/index.html?highlight=fetchval#cursors
    #     """

    #     async with self.pool.acquire() as conn:
    #         return await conn.fetch(
    #             "SELECT dpapi_blob_id, is_file, enc_data_bytes, enc_data_object_id FROM nemesis.dpapi_blobs WHERE masterkey_guid = $1 AND is_decrypted = False",
    #             masterkey_guid,
    #         )

    # async def get_decrypted_dpapi_masterkey(self, masterkey_guid: str):
    #     """Returns (decrypted_key_sha1, decrypted_key_full) for a decrypted DPAPI masterkey or None for no results."""

    #     async with self.pool.acquire() as conn:
    #         row = await conn.fetchrow(
    #             "SELECT decrypted_key_sha1, decrypted_key_full FROM nemesis.dpapi_masterkeys WHERE masterkey_guid = $1 AND is_decrypted = True",
    #             masterkey_guid,
    #         )
    #         return (row[0], row[1]) if row else None

    # async def get_dpapi_domain_backupkey(self, domain_backupkey_guid: str) -> Optional[bytes]:
    #     """Returns the raw bytes of a domain DPAPI backup key for a given GUID if it exists."""

    #     async with self.pool.acquire() as conn:
    #         row = await conn.fetchrow(
    #             "SELECT domain_backupkey_bytes FROM nemesis.dpapi_domain_backupkeys WHERE domain_backupkey_guid = $1",
    #             domain_backupkey_guid,
    #         )
    #         return row[0] if row else None

    # async def update_decrypted_dpapi_masterkey(self, masterkey_guid: str, decrypted_key_sha1: bytes, decrypted_key_full: bytes) -> None:
    #     """Updates the (decrypted_key_sha1, decrypted_key_full) values for a DPAPI masterkey."""

    #     query = "UPDATE nemesis.dpapi_masterkeys SET decrypted_key_sha1 = $1, decrypted_key_full = $2, is_decrypted = True WHERE masterkey_guid = $3"

    #     async with self.pool.acquire() as conn:
    #         await conn.execute(query, decrypted_key_sha1, decrypted_key_full, masterkey_guid)

    # async def update_decrypted_dpapi_blob(
    #     self,
    #     dpapi_blob_id: uuid.UUID,
    #     dec_data_bytes: Optional[bytes],
    #     dec_data_object_id: Optional[UUID],
    # ) -> None:
    #     """Updates the (decrypted_key_sha1, decrypted_key_full) values for a DPAPI masterkey.

    #     If the decrypted data is over 1024 bytes, a dec_data_object_id should be passed instead.
    #     """

    #     if dec_data_bytes:
    #         query = "UPDATE nemesis.dpapi_blobs SET dec_data_bytes = $1, is_decrypted = True WHERE dpapi_blob_id = $2"
    #         async with self.pool.acquire() as conn:
    #             await conn.execute(query, dec_data_bytes, dpapi_blob_id)
    #     elif dec_data_object_id:
    #         query = "UPDATE nemesis.dpapi_blobs SET dec_data_object_id = $1, is_decrypted = True WHERE dpapi_blob_id = $2"
    #         async with self.pool.acquire() as conn:
    #             await conn.execute(query, dec_data_object_id, dpapi_blob_id)

    # async def get_decrypted_chromium_state_key(self, source: str, user_data_directory: str):
    #     """Returns the bytes of a decrypted state key file or None for no results."""

    #     async with self.pool.acquire() as conn:
    #         row = await conn.fetchrow(
    #             "SELECT key_bytes_dec FROM nemesis.chromium_state_files WHERE source = $1 AND user_data_directory = $2 AND is_decrypted = True",
    #             source,
    #             user_data_directory,
    #         )
    #         return (row[0]) if row else None

    # async def get_encrypted_chromium_state_key(self, masterkey_guid: str) -> List[Tuple[str, str, uuid.UUID, bytes, bytes]]:
    #     """Gets encrypted Chromium state key entries linked to a specific masterkey guid.

    #     TODO: Use cursors to handle lots of results https://magicstack.github.io/asyncpg/current/api/index.html?highlight=fetchval#cursors
    #     """

    #     async with self.pool.acquire() as conn:
    #         return await conn.fetch(
    #             "SELECT source, user_data_directory, unique_db_id, key_bytes_enc, app_bound_fixed_data_enc FROM nemesis.chromium_state_files WHERE masterkey_guid = $1 AND is_decrypted = False",
    #             masterkey_guid,
    #         )

    # async def update_decrypted_chromium_state_key(self, unique_db_id: UUID4, key_bytes_dec: bytes, app_bound_fixed_data_dec: bytes | None) -> None:
    #     """Updates the decrypted state key values for a Chromium Local State file."""

    #     query = "UPDATE nemesis.chromium_state_files SET key_bytes_dec = $1, is_decrypted = True WHERE unique_db_id = $2"
    #     async with self.pool.acquire() as conn:
    #         await conn.execute(query, key_bytes_dec, unique_db_id)

    #     if app_bound_fixed_data_dec and app_bound_fixed_data_dec is not None:
    #         query = "UPDATE nemesis.chromium_state_files SET app_bound_fixed_data_dec = $1 WHERE unique_db_id = $2"
    #         async with self.pool.acquire() as conn:
    #             await conn.execute(query, key_bytes_dec, unique_db_id)

    # async def get_dpapi_encrypted_chromium_logins(self, masterkey_guid: str) -> List[Tuple[uuid.UUID, bytes]]:
    #     """Gets DPAPI encrypted Chromium Logins entries linked to a specific masterkey guid.

    #     TODO: Use cursors to handle lots of results https://magicstack.github.io/asyncpg/current/api/index.html?highlight=fetchval#cursors
    #     """

    #     async with self.pool.acquire() as conn:
    #         return await conn.fetch(
    #             "SELECT unique_db_id,password_value_enc FROM nemesis.chromium_logins WHERE masterkey_guid = $1 AND is_decrypted = False",
    #             masterkey_guid,
    #         )

    # async def get_aes_encrypted_chromium_logins(self, source: str, user_data_directory: str) -> List[Tuple[uuid.UUID, bytes]]:
    #     """Gets AES encrypted Chromium Logins entries linked to a specific source/data directory.

    #     TODO: Use cursors to handle lots of results https://magicstack.github.io/asyncpg/current/api/index.html?highlight=fetchval#cursors
    #     """

    #     async with self.pool.acquire() as conn:
    #         return await conn.fetch(
    #             "SELECT unique_db_id,password_value_enc FROM nemesis.chromium_logins WHERE encryption_type = 'aes' and source = $1 AND user_data_directory = $2 AND is_decrypted = False",
    #             source,
    #             user_data_directory,
    #         )

    # async def update_decrypted_chromium_login(self, unique_db_id: UUID4, password_value_dec: str) -> None:
    #     """Updates a decrypted password value for a Chromium Logins file."""

    #     query = "UPDATE nemesis.chromium_logins SET password_value_dec = $1, is_decrypted = True WHERE unique_db_id = $2"
    #     async with self.pool.acquire() as conn:
    #         await conn.execute(query, password_value_dec, unique_db_id)

    # async def get_dpapi_encrypted_chromium_cookies(self, masterkey_guid: str) -> List[Tuple[uuid.UUID, bytes]]:
    #     """Gets DPAPI encrypted Chromium Cookies entries linked to a specific masterkey guid.

    #     TODO: Use cursors to handle lots of results https://magicstack.github.io/asyncpg/current/api/index.html?highlight=fetchval#cursors
    #     """

    #     async with self.pool.acquire() as conn:
    #         return await conn.fetch(
    #             "SELECT unique_db_id,value_enc FROM nemesis.chromium_cookies WHERE masterkey_guid = $1 AND is_decrypted = False",
    #             masterkey_guid,
    #         )

    # async def get_aes_encrypted_chromium_cookies(self, source: str, user_data_directory: str) -> List[Tuple[uuid.UUID, bytes]]:
    #     """Gets AES encrypted Chromium Cookies entries linked to a specific source/data directory.

    #     TODO: Use cursors to handle lots of results https://magicstack.github.io/asyncpg/current/api/index.html?highlight=fetchval#cursors
    #     """

    #     async with self.pool.acquire() as conn:
    #         return await conn.fetch(
    #             "SELECT unique_db_id,value_enc FROM nemesis.chromium_cookies WHERE encryption_type = 'aes' AND source = $1 AND user_data_directory = $2 AND is_decrypted = False",
    #             source,
    #             user_data_directory,
    #         )

    # async def update_decrypted_chromium_cookie(self, unique_db_id: UUID4, value_dec: str) -> None:
    #     """Updates a decrypted password value for a Chromium Cookies file."""

    #     query = "UPDATE nemesis.chromium_cookies SET value_dec = $1, is_decrypted = True WHERE unique_db_id = $2"
    #     async with self.pool.acquire() as conn:
    #         await conn.execute(query, value_dec, unique_db_id)

    async def is_file_processed(self, file_sha256: str) -> bool:
        """Takes the sha256 of a file and returns whether the file has already been processed."""

        async with self.pool.acquire() as conn:
            v = await conn.fetch(
                "SELECT EXISTS (SELECT true FROM nemesis.file_data_enriched WHERE sha256 = $1)", file_sha256
            )
            return v[0][0] is True

    # async def sanitize_identifier(self, identifier: str) -> str:
    #     """Sanitizes a postgres column names to make it safe for use in dynamic queries

    #     Args:
    #         identifier (str): The identifier to sanitize (e.g., a user-supplied column name)

    #     Returns:
    #         str: The sanitized identifier.
    #     """

    #     async with self.pool.acquire() as conn:
    #         sanitized = await conn.fetchval("SELECT quote_ident($1)", identifier)
    #         return sanitized
