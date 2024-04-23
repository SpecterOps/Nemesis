from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

import sqlalchemy
from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    Computed,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    SmallInteger,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Custom Postgres Types
# PositiveInteger = DOMAIN(
#     name="PositiveInteger",
#     data_type=Integer,
#     not_null=False,
#     check=r"VALUE > 0",
# )

# Models
class Base(DeclarativeBase):
    pass

class ApiDataMessage(Base):
    __tablename__ = "api_data_messages"
    __table_args__ = {
        "comment": "Messages containing data collected from agents. All incoming data POST messages sent to Nemesis are stored here in their raw form and are replayed during when/if data is reprocessed."
    }

    message_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
    )
    message_bytes: Mapped[bytes] = mapped_column(LargeBinary)
    expiration: Mapped[datetime] = mapped_column(DateTime)


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = {
        "comment": "Project information. Each piece of ingested data is associated with a project in this table."
    }

    id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        unique=True,
    )
    name: Mapped[str] = mapped_column(Text, unique=True, comment="The project's name")
    timestamp: Mapped[datetime] = mapped_column(DateTime, comment="Timestamp when the project was created")
    expiration: Mapped[datetime.date] = mapped_column(
        Date, comment="Date when in the project expires. Format: YYYY-MM-DD"
    )


class ProjectDEPRECATED:
    """Base class for all data collection types.
    This class is deprecated and will be removed in the future.
    Types that have not migrated to the new host data model still use this class.
    """

    project_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        ForeignKey("projects.id"),
        nullable=False,
        comment="Project associated with the data",
    )
    source: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Source of the data. Value depends on the type of data collection. e.g., for host data, this is the hostname.",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        comment="Timestamp of when the data was created/collected.",
    )
    expiration: Mapped[datetime.date] = mapped_column(
        Date,
        nullable=False,
        comment="Date when in the data expires. Format: YYYY-MM-DD",
    )


class AgentHostMapping(Base):
    __tablename__ = "agent_host_mappings"
    __table_args__ = {
        "comment": "Maps an agent to a host. Each agent is associated with at least a single host and potentially more if it collects data from a remote host."
    }

    id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        unique=True,
        comment="Unique row identifier for each agent_host_mapping. Each agent's host_mapping_id column will map to a single row in this table.",
    )
    project_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        ForeignKey("projects.id"),
        comment="Project associated with the host",
    )
    host_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="ID used to collapse hosts together. Data associated with the same host should have the same host_id value and likewise differing hosts should have different host_id values.",
    )

    # Host information (TODO: move to separate table)
    shortname: Mapped[str | None] = mapped_column(
        Text, comment="Short name of the host (e.g. hostname or NetBIOS name)"
    )
    longname: Mapped[str | None] = mapped_column(Text, comment="Long name of the host (e.g. FQDN)")
    ip_address: Mapped[IPv4Address | IPv6Address | None] = mapped_column(INET, comment="IP address of the host")


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint(
            "agent_id",
            "agent_type",
            "project_id",
            name="agents_agent_id_agent_type_project_id_key",
            comment="Constraint ensuring each agent in a project is unique",
        ),
        {"comment": "Basic information surfaced about collection agents that have submitted data"},
    )

    id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        unique=True,
        comment="Unique row identifier for each agent",
    )
    project_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        ForeignKey("projects.id"),
        comment="Project associated with the agent",
    )
    agent_id: Mapped[str] = mapped_column(
        Text,
        comment="C2 identifier of the agent that collected the data (beacon: 12345, mythic: <GUID>, etc.)",
    )
    agent_type: Mapped[str] = mapped_column(
        Text,
        comment="String describing the type of agent (beacon, apollo, stage1, etc.)",
    )
    host_mapping_id: Mapped[int] = mapped_column(
        sqlalchemy.UUID(),
        ForeignKey("agent_host_mappings.id"),
        nullable=False,
        unique=True,  # Ensure each agent has a unique mapping to a host
        comment="Points to the host mapping for agent. For each agent, there is a single agent_host_mappings row that maps it to a host (i.e., there is a 1:1 relationship between agents and agent host mappings)",
    )


class BaseOdrObject:
    """Base class for all data collection types.
    """
    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        server_default=text("gen_random_uuid()"),
        primary_key=True,
        nullable=False,
    )

    message_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        ForeignKey("api_data_messages.message_id"),
        nullable=False,
        comment="Original message ID assigned during data ingestion",
    )

    project_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        ForeignKey("projects.id"),
        nullable=False,
        comment="Project associated with the data",
    )

    timestamp: Mapped[datetime] = mapped_column(DateTime, comment="Timestamp of when the data was created/collected.")

    expiration: Mapped[datetime.date] = mapped_column(Date, comment="Date when in the data expires. Format: YYYY-MM-DD")

    agent_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        ForeignKey("agents.id"),
        nullable=False,
        comment="ID of the agent that collected the data",
    )

    originating_object_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        ForeignKey("api_data_messages.message_id"),
        nullable=True,
        comment="Message ID of the object that the data originated from. For example, registry keys originating from a registry hive file, or credentials originating from a file.",
    )


class DataOperation(StrEnum):
    list = "list"
    add = "add"
    remove = "remove"


class DataCollection(BaseOdrObject):
    """Base class for all data collection types."""

    operation: Mapped[DataOperation] = mapped_column(
        Enum(DataOperation),
        nullable=False,
        comment="Type of operation: list, add, or remove",
    )
    # source: Mapped[str] = mapped_column(
    #     Text,
    #     nullable=False,
    #     comment="Source of the data. Value depends on the type of data collection. e.g., for host data, this is the hostname.",
    # )


class HostDataCollection(DataCollection):
    """Base class for all host data types.
    Contains properties and relationships common to all host data types.
    """

    host_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        ForeignKey("agent_host_mappings.id"),
        nullable=False,
        comment="Identifies the host the data is currently mapped to",
    )
    is_data_remote: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        comment="Is the data for a remote host? Or was it enumerated locally on the current machine?",
    )
    # # Not needed now since we can crawl back to the agent via the host mapping table
    # agent_id: Mapped[UUID] = mapped_column(
    #     sqlalchemy.UUID(),
    #     ForeignKey("agents.id"),
    #     nullable=False,
    #     comment="ID of the agent that collected the data",
    # )


########################################################################
# Host Data Types
########################################################################
class FileSystemObjectType(StrEnum):
    file = "file"
    folder = "folder"


class FileSystemObject(HostDataCollection, Base):
    __tablename__ = "filesystem_objects"
    __table_args__ = (
        Index(
            "filesystem_objects_on_path_idx",
            "path",
            postgresql_using="gin",
            postgresql_ops={"path": "gin_trgm_ops"},
        ),
        {
            "comment": "Filesystem objects (files and folders) collected from a host, whether through downloads or listings."
        },
    )

    path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Path to the file or folder",
    )
    name: Mapped[str | None] = mapped_column(
        Text,
        comment="Name of the file or folder",
    )
    extension: Mapped[str | None] = mapped_column(
        Text,
        comment="File extension",
    )
    type: Mapped[FileSystemObjectType] = mapped_column(
        Enum(FileSystemObjectType),
        nullable=False,
        comment="Type of object: file or folder",
    )
    size: Mapped[int | None] = mapped_column(
        Integer,
        comment="Size of the file in bytes",
    )
    magic_type: Mapped[str | None] = mapped_column(
        Text,
        comment="Type of the file (derived from sniffing the file's content)",
    )
    creation_time: Mapped[datetime | None] = mapped_column(
        DateTime,
        comment="Time the file was created",
    )
    access_time: Mapped[datetime | None] = mapped_column(
        DateTime,
        comment="Time the file was last accessed",
    )
    modification_time: Mapped[datetime | None] = mapped_column(
        DateTime,
        comment="Time the file was last modified",
    )
    access_mode: Mapped[int | None] = mapped_column(
        Integer,
        comment="File access mode (*nix permission number)",
    )
    file_group: Mapped[str | None] = mapped_column(
        Text,
        comment="File group (*nix case sensitive file group membership)",
    )
    file_id: Mapped[str | None] = mapped_column(
        Text,
        comment="File ID (*nix string for an inode or file id)",
    )
    owner: Mapped[str | None] = mapped_column(
        Text,
        comment="Case sensitive owner (*nix and Windows)",
    )
    sddl: Mapped[str | None] = mapped_column(
        Text,
        comment="Security Descriptor Definition Language (SDDL) string",
    )
    nemesis_file_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        comment="Nemesis-assigned unique identifier for the file",
    )


class FileDataEnriched(HostDataCollection, Base):
    __tablename__ = "file_data_enriched"
    __table_args__ = {
        "comment": "An in-between the Elastic and Postgres representations for enriched data. This is for ease of use of searching/filtering through the dashboard(s)",
    }

    object_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        nullable=False,
        unique=True,
        comment="Nemesis file UUID of the file",
    )
    path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="The file's path",
    )
    name: Mapped[str | None] = mapped_column(
        Text,
        comment="The file's name",
    )
    size: Mapped[int | None] = mapped_column(
        BigInteger,
        comment="Size of the file in bytes",
    )
    md5: Mapped[str | None] = mapped_column(
        Text,
        comment="MD5 hash of the file",
    )
    sha1: Mapped[str | None] = mapped_column(
        Text,
        comment="SHA1 hash of the file",
    )
    sha256: Mapped[str | None] = mapped_column(
        Text,
        comment="SHA256 hash of the file",
    )
    nemesis_file_type: Mapped[str | None] = mapped_column(
        Text,
        comment="Nemesis-derived file type",
    )
    magic_type: Mapped[str | None] = mapped_column(
        Text,
        comment="Magic type of the file (derived from sniffing the file's content via libmagic)",
    )
    converted_pdf_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        comment="Nemesis file UUID if there's a converted PDF linked to this file",
    )
    extracted_plaintext_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        comment="Nemesis file UUID if there's extracted plaintext linked to this file",
    )
    extracted_source_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        comment="Nemesis file UUID if there's extracted source code linked to this file",
    )
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text),
        nullable=True,
        comment="List of tags associated with the file (e.g., hash_dpapi, has_deserialization, etc.)",
    )
    # Not included since BaseObjectOdr has it
    # originating_object_id: Mapped[Optional[UUID]] = mapped_column(
    #     sqlalchemy.UUID(),
    #     comment="Nemesis UUID referencing the original file the dpapi blob was extracted from",
    # )


class RegistryObject(HostDataCollection, Base):
    __tablename__ = 'registry_objects'
    __table_args__ = (
        {"comment": "Registry entry objects"},
    )

    key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Registry key"
    )
    value_name: Mapped[str | None] = mapped_column(
        Text,
        comment="Name of the registry value"
    )
    value_kind: Mapped[int | None] = mapped_column(
        Integer,
        comment="The registry value's data type"
    )
    value: Mapped[str | None] = mapped_column(
        Text,
        comment="Content of the registry value"
    )
    sddl: Mapped[str | None] = mapped_column(
        Text,
        comment="Security Descriptor Definition Language (SDDL) string for the registry object"
    )
    tags: Mapped[str | None] = mapped_column(
        Text,
        comment="Tags associated with the registry object"
    )


class Service(HostDataCollection, Base):
    __tablename__ = 'services'
    __table_args__ = (
        {"comment": "Windows services, derived from registry values or submitted manually"},
    )

    binary_path: Mapped[str | None] = mapped_column(
        Text,
        comment="Filesystem path to the service's binary"
    )
    command_line: Mapped[str | None] = mapped_column(
        Text,
        comment="Command line used to start the service"
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        comment="Description of the service"
    )
    display_name: Mapped[str | None] = mapped_column(
        Text,
        comment="Display name of the service"
    )
    name: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Name of the service"
    )
    sddl: Mapped[str | None] = mapped_column(
        Text,
        comment="Security Descriptor Definition Language (SDDL) string for the service"
    )
    service_dll_entrypoint: Mapped[str | None] = mapped_column(
        Text,
        comment="Entrypoint function name in the service DLL"
    )
    service_dll_path: Mapped[str | None] = mapped_column(
        Text,
        comment="Filesystem path to the service DLL"
    )
    service_type: Mapped[int | None] = mapped_column(
        SmallInteger,
        comment="Type of the service"
    )
    start_type: Mapped[int | None] = mapped_column(
        SmallInteger,
        comment="How the service starts"
    )
    state: Mapped[int | None] = mapped_column(
        SmallInteger,
        comment="Current state of the service"
    )
    username: Mapped[str | None] = mapped_column(
        Text,
        comment="Username under which the service runs"
    )
    filesystem_object_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        ForeignKey('filesystem_objects.unique_db_id'),
        comment="Reference to the service file if it's been downloaded"
    )


class NamedPipe(HostDataCollection, Base):
    __tablename__ = "named_pipes"
    __table_args__ = {"comment": "Windows named pipes, derived Seatbelt data or submitted manually"}

    name: Mapped[str] = mapped_column(
        Text,
        comment="The pipe's name",
    )
    server_process_id: Mapped[int | None] = mapped_column(
        Integer,
        comment="Process ID that created the pipe",
    )
    server_process_name: Mapped[str | None] = mapped_column(
        Text,
        comment="Name of the process that created the pipe",
    )
    server_process_path: Mapped[str | None] = mapped_column(
        Text,
        comment="Full path to the process that created the pipe",
    )
    server_process_session_id: Mapped[int | None] = mapped_column(
        Integer,
        comment="Session ID of the process that created the pipe",
    )
    sddl: Mapped[str | None] = mapped_column(
        Text,
        comment="Security Descriptor Definition Language (SDDL) string for the pipe",
    )


class Process(HostDataCollection, Base):
    __tablename__ = "processes"
    __table_args__ = (
        CheckConstraint(
            "(name IS NOT NULL AND name <> '') OR process_id IS NOT NULL"
        ),  # Ensure the name or process_id is populated
        {"comment": "Represents a process running on a host. At a minimum, a process needs a name and/or process ID."},
    )

    name: Mapped[str | None] = mapped_column(
        Text,
        comment="The process's name",
        nullable=True,
    )
    command_line: Mapped[str | None] = mapped_column(
        Text,
        comment="A process's command line",
        nullable=True,
    )
    file_name: Mapped[str | None] = mapped_column(
        Text,
        comment="Path to the file",
        nullable=True,
    )
    process_id: Mapped[int | None] = mapped_column(
        Integer,
        comment="Process ID",
        nullable=True,
    )
    parent_process_id: Mapped[int | None] = mapped_column(
        Integer,
        comment="Parent process's PID",
        nullable=True,
    )
    architecture: Mapped[str | None] = mapped_column(
        Text,
        comment="Process's architecture",
        nullable=True,
    )
    username: Mapped[str | None] = mapped_column(
        Text,
        comment="The process's username",
        nullable=True,
    )

    # Enriched data
    category: Mapped[str | None] = mapped_column(
        Text,
        comment="Enriched category of the process",
        nullable=True,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        comment="Enriched category's description",
        nullable=True,
    )


########################################################################
# DPAPI
#     TODO: Review all DPAPI stuff because host-modeling changed tables significantly
########################################################################


class DpapiBlob(ProjectDEPRECATED, Base):
    __tablename__ = "dpapi_blobs"
    __table_args__ = (
        # Ensure either enc_data_object_id or enc_data_object_id is set, not both (and their corresponding decrypted data columns)
        CheckConstraint(
            "(is_file = False AND enc_data_bytes IS NOT NULL AND enc_data_object_id IS NULL AND dec_data_object_id IS NULL)"  # If it's not a file, ensure there's an encrypted bytes column and no encrypted/decrypted file UUID columns
            " OR "
            "(is_file = True AND enc_data_bytes IS NULL AND enc_data_object_id IS NOT NULL AND dec_data_bytes IS NULL)",  # If it's a file, ensure there's an encrypted file UUID column and no encrypted/decrypted bytes columns
            name="dpapi_blobs_check_enc_dec_data_consistency",
        ),
        # Decryption column constraints
        CheckConstraint(
            "(is_decrypted = False AND (dec_data_bytes IS NULL AND dec_data_object_id IS NULL))"  # If it's not decrypted, then decryption columns should be null
            " OR "
            "(is_decrypted = True AND (dec_data_bytes IS NOT NULL OR dec_data_object_id IS NOT NULL))",  # If it's decrypted, then one of the decryption columns should be not null (both won't be due to previous constraint)
            name="dpapi_blobs_check_dec_data_presence_if_decrypted",
        ),
        {
            "comment": "Contains extracted DPAPI blobs in their encrypted and/or decrypted forms.",
        },
    )

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique row identifier for each DPAPI blob",
    )
    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="C2 identifier of the agent that collected the data (beacon: 12345, mythic: <GUID>, etc.)",
    )
    # TODO: Replace this with unique_db_id
    dpapi_blob_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Nemesis-assigned unique identifier for the DPAPI blob",
    )
    originating_object_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="Nemesis UUID referencing the original file the dpapi blob was extracted from",
    )
    originating_registry_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="Nemesis UUID referencing the registry key the dpapi blob was extracted from",
    )
    masterkey_guid: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        nullable=False,
        comment="GUID of the masterkey associated with the DPAPI blob",
    )
    is_file: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        comment="Is the DPAPI blob associated with a Nemesis file UUID? If true, the extracted DPAPI blob too big to be stored as bytes in the DB and instead is stored as a file within Nemesis.",
    )
    is_decrypted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        comment="Is the DPAPI blob decrypted?",
    )
    enc_data_bytes: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="Bytes of the encrypted data (if less than 1024 bytes). Otherwise, use the enc_data_object_id column.",
    )
    enc_data_object_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="If the encrypted data is > 1024 bytes, the Nemesis file UUID containing the encrypted data",
    )
    dec_data_bytes: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="Decrypted DPAPI blob data (if less that 1024 bytes). Otherwise, the use the dec_data_object_id column",
    )
    dec_data_object_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="If the decrypted data is > 1024 bytes, the Nemesis file UUID containing the decrytped data",
    )


class DpapiDomainBackupKey(ProjectDEPRECATED, Base):
    __tablename__ = "dpapi_domain_backupkeys"
    __table_args__ = {
        "comment": "Contains extracted DPAPI domain backup keys.",
    }

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique row identifier for each DPAPI blob",
    )
    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="C2 identifier of the agent that collected the data (beacon: 12345, mythic: <GUID>, etc.)",
    )
    domain_backupkey_guid: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        nullable=False,
        primary_key=True,
        comment="GUID of the domain backup key. Linked to dpapi_masterkeys.domain_backupkey_guid",
    )
    domain_controller: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Domain controller from which the backup key was extracted",
    )
    domain_backupkey_bytes: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
        comment="Bytes of the domain's DPAPI backup private key",
    )

# TODO: Add this to DpapiMasterKeys
class DpapiMasterKeyUserType(StrEnum):
    domain_user = "domain_user"
    local_user = "local_user"
    machine = "machine"


class DpapiMasterKeys(ProjectDEPRECATED, Base):
    __tablename__ = "dpapi_masterkeys"
    __table_args__ = {
        "comment": "Contains individual extracted DPAPI master keys.",
    }

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique row identifier for each DPAPI blob",
    )
    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="C2 identifier of the agent that collected the data (beacon: 12345, mythic: <GUID>, etc.)",
    )
    object_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="Nemesis file UUID of the master key",
    )
    type: Mapped[Text | None] = mapped_column(  # TODO: Migrate this to use the enum DpapiMasterKeyUserType
        Text,
        nullable=True,
        comment="Type of user the master key belongs to (domain_user, local_user, or machine)",
    )
    username: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Username of the user who owns the master key",
    )
    user_sid: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Security Identifier(SID) of the user who owns the master key",
    )
    masterkey_guid: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        nullable=False,
        primary_key=True,
        comment="GUID of the master key. If a blob can be decrypted, dpapi_blobs.masterkey_guid should match this value.",
    )
    is_decrypted: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment="Is the master key decrypted?",
    )
    masterkey_bytes: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="Bytes of the master key",
    )
    domain_backupkey_guid: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="GUID of the domain backup key. Linked to dpapi_domain_backupkeys.domain_backupkey_guid",
    )
    domainkey_pb_secret: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="Encrypted master key. Associated domain backup key can decrypt this.",
    )
    decrypted_key_full: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="Decrypted master key",
    )
    decrypted_key_sha1: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="SHA1 representation of the master key",
    )


########################################################################
# Chromium
#    TODO: Migrate to host model
########################################################################
class ChromiumHistoryEntry(ProjectDEPRECATED, Base):
    __tablename__ = "chromium_history"
    __table_args__ = (
        UniqueConstraint(
            "source",
            "agent_id",
            "originating_object_id",
            "index_md5_hash",
            name="chromium_history_url_unique_constraint",
            comment="Constraint ensuring each history entry on a host+agent is unique",
        ),
        {
            "comment": "Entries from a Chromium browser's History database (stored in the 'urls' table)",
        },
    )

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique row identifier for each Chromium history entry",
    )
    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="C2 identifier of the agent that collected the data (beacon: 12345, mythic: <GUID>, etc.)",
    )
    originating_object_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="Nemesis file UUID if this entry originated from a file",
    )
    user_data_directory: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Specific user Chromium data directory path, if applicable",
    )
    username: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Username extracted from user_data_directory, if applicable",
    )
    browser: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Browser name extracted from user_data_directory, if applicable (Example: chrome)",
    )
    url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="URL extracted from the Chromium DB",
    )
    title: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Title extracted from the Chromium DB",
    )
    visit_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Visit count extracted from the Chromium DB",
    )
    typed_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        comment="Typed count extracted from the Chromium DB",
    )
    last_visit_time: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
        comment="Last visit time extracted from the Chromium DB",
    )
    index_md5_hash: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        Computed("MD5(user_data_directory || url)::uuid"),
        nullable=False,
        comment="MD5 hash of the user_data_directory and url. Computed to deal with length limits for the UNIQUE constraint (URLs often exceed length limit)",
    )


class ChromiumDownload(ProjectDEPRECATED, Base):
    __tablename__ = "chromium_downloads"
    __table_args__ = (
        UniqueConstraint(
            "source",
            "agent_id",
            "originating_object_id",
            "index_md5_hash",
            name="chromium_downloads_url_unique_constraint",
            comment="Constraint ensuring each history entry on a host+agent is unique",
        ),
        {
            "comment": "Entries from the 'downloads' table in a Chromium History database",
        },
    )

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique row identifier for each Chromium download entry",
    )
    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="C2 identifier of the agent that collected the data (beacon: 12345, mythic: <GUID>, etc.)",
    )
    originating_object_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="Nemesis file UUID if this entry originated from a file",
    )
    user_data_directory: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Specific user Chromium data directory path, if applicable",
    )
    username: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Username extracted from user_data_directory, if applicable",
    )
    browser: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Browser name extracted from user_data_directory, if applicable (Example: chrome)",
    )
    url: Mapped[str] = mapped_column(
        Text,
        nullable=True,
        comment="extracted from the Chromium DB 'tab_url' field",
    )
    download_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Extracted from the Chromium DB 'target_path' field",
    )
    start_time: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=True,
        comment="extracted from the Chromium DB",
    )
    end_time: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
        comment="extracted from the Chromium DB",
    )
    total_bytes: Mapped[int] = mapped_column(
        Integer,
        nullable=True,
        comment="extracted from the Chromium DB",
    )
    danger_type: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="extracted from the Chromium DB, converted from int",
    )
    index_md5_hash: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        Computed("MD5(user_data_directory || download_path)::uuid"),
        nullable=False,
        comment="MD5 hash of the user_data_directory and download_path. Computed to deal with length limits for the UNIQUE constraint",
    )


class ChromiumLogin(ProjectDEPRECATED, Base):
    __tablename__ = "chromium_logins"
    __table_args__ = (
        UniqueConstraint(
            "source",
            "agent_id",
            "originating_object_id",
            "index_md5_hash",
            "password_value_enc",
            name="chromium_logins_unique_constraint",
            comment="Constraint ensuring each login entry is unique",
        ),
        {
            "comment": "Entries from the 'logins' table in a Chromium 'Login Data' database",
        },
    )

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique row identifier for each Chromium login entry",
    )
    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="C2 identifier of the agent that collected the data (beacon: 12345, mythic: <GUID>, etc.)",
    )
    originating_object_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="Nemesis file UUID if this entry originated from a file",
    )
    user_data_directory: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Specific user Chromium data directory path, if applicable",
    )
    username: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Username extracted from user_data_directory, if applicable",
    )
    browser: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Browser name extracted from user_data_directory, if applicable (Example: chrome)",
    )
    origin_url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="extracted from the Chromium DB",
    )
    username_value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="extracted from the Chromium DB",
    )
    password_value_enc: Mapped[bytes | None] = mapped_column(
        LargeBinary,
        nullable=True,
        comment="extracted from the Chromium DB 'password_value' field",
    )
    signon_realm: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="extracted from the Chromium DB",
    )
    date_created: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
        comment="extracted from the Chromium DB",
    )
    date_last_used: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
        comment="extracted from the Chromium DB",
    )
    date_password_modified: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
        comment="extracted from the Chromium DB",
    )
    times_used: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="extracted from the Chromium DB",
    )
    encryption_type: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="carved from the 'password_value_enc' bytes",
    )
    masterkey_guid: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="if encryption_type==dpapi, linked to 'masterkey_guid' in dpapi_masterkeys",
    )
    is_decrypted: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment="Is the password decrypted?",
    )
    password_value_dec: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Decrypted password value",
    )
    index_md5_hash: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        Computed("MD5(user_data_directory || origin_url || username_value)::uuid"),
        nullable=False,
        comment="MD5 hash of the user_data_directory, origin_url, and username_value. Computed to deal with length limits for the UNIQUE constraint",
    )


# See https://chromium.googlesource.com/chromium/src/net/+/refs/heads/main/extras/sqlite/sqlite_persistent_cookie_store.cc#123
class ChromiumCookie(ProjectDEPRECATED, Base):
    __tablename__ = "chromium_cookies"
    __table_args__ = (
        UniqueConstraint(
            "source",
            "agent_id",
            "originating_object_id",
            "index_md5_hash",
            name="chromium_cookies_unique_constraint",
            comment="Constraint ensuring each cookie entry is unique",
        ),
        {
            "comment": "Entries from the 'cookies' table in a Chromium 'Cookies' database",
        },
    )

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique row identifier for each Chromium cookie entry",
    )
    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="C2 identifier of the agent that collected the data (beacon: 12345, mythic: <GUID>, etc.)",
    )
    originating_object_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(), nullable=True, comment="Nemesis file UUID if this entry originated from a file"
    )
    user_data_directory: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Specific user Chromium data directory path, if applicable"
    )
    username: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Username extracted from user_data_directory, if applicable"
    )
    browser: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Browser name extracted from user_data_directory, if applicable (Example: chrome)"
    )
    host_key: Mapped[str] = mapped_column(Text, nullable=False, comment="Extracted from the Chromium DB")
    name: Mapped[str] = mapped_column(Text, nullable=False, comment="Extracted from the Chromium DB")
    path: Mapped[str] = mapped_column(Text, nullable=False, comment="Extracted from the Chromium DB")
    creation_utc: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Extracted from the Chromium DB"
    )
    expires_utc: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Extracted from the Chromium DB"
    )
    last_access_utc: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Extracted from the Chromium DB"
    )
    last_update_utc: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Extracted from the Chromium DB"
    )
    is_secure: Mapped[bool | None] = mapped_column(Boolean, nullable=True, comment="Extracted from the Chromium DB")
    is_httponly: Mapped[bool | None] = mapped_column(Boolean, nullable=True, comment="Extracted from the Chromium DB")
    is_session: Mapped[bool | None] = mapped_column(Boolean, nullable=True, comment="Extracted from the Chromium DB")
    samesite: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Extracted from the Chromium DB, translated from int"
    )
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True, comment="Extracted from the Chromium DB")
    value_enc: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True, comment="Extracted from the Chromium DB 'encrypted_value' field"
    )
    encryption_type: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Carved from the 'value_enc' bytes"
    )
    masterkey_guid: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(),
        nullable=True,
        comment="If encryption_type==dpapi, linked to 'masterkey_guid' in dpapi_masterkeys",
    )
    is_decrypted: Mapped[bool | None] = mapped_column(Boolean, nullable=True, comment="Is the value decrypted?")
    value_dec: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Decrypted value")
    index_md5_hash: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        Computed("MD5(user_data_directory || host_key || name || path)::uuid"),
        nullable=False,
        comment="MD5 hash of the user_data_directory, host_key, name, and path. Computed to deal with length limits for the UNIQUE constraint",
    )


class ChromiumStateFile(ProjectDEPRECATED, Base):
    __tablename__ = "chromium_state_files"
    __table_args__ = (
        UniqueConstraint(
            "source",
            "agent_id",
            "originating_object_id",
            "user_data_directory",
            name="chromium_state_files_unique_constraint",
            comment="Constraint ensuring each state file entry is unique",
        ),
        {
            "comment": "Information/encrypted key from a Chromium 'Local State' file used to encrypt new Chromium logins/cookies",
        },
    )

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique row identifier for each Chromium state file entry",
    )
    agent_id: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="C2 identifier of the agent that collected the data (beacon: 12345, mythic: <GUID>, etc.)",
    )
    originating_object_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(), nullable=True, comment="Nemesis file UUID if this entry originated from a file"
    )
    user_data_directory: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Specific user Chromium data directory path, if applicable"
    )
    username: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Username extracted from user_data_directory, if applicable"
    )
    browser: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Browser name extracted from user_data_directory, if applicable (Example: chrome)"
    )
    installation_date: Mapped[Date | None] = mapped_column(
        Date, nullable=True, comment="Extracted from the Chromium 'Local State' file"
    )
    launch_count: Mapped[int | None] = mapped_column(
        Integer, nullable=True, comment="Extracted from the Chromium 'Local State' file"
    )
    masterkey_guid: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(), nullable=True, comment="Linked to 'masterkey_guid' in dpapi_masterkeys"
    )
    key_bytes_enc: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False, comment="Extracted from the Chromium 'Local State' file"
    )
    app_bound_fixed_data_enc: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False, comment="Extracted from the Chromium 'Local State' file"
    )
    is_decrypted: Mapped[bool | None] = mapped_column(Boolean, nullable=True, comment="Is the key decrypted?")
    key_bytes_dec: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, comment="Decrypted key bytes")
    app_bound_fixed_data_dec: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False, comment="Decrypted application bound fixed data"
    )


########################################################################
# Slack data
#    TODO: Migrate to host model
########################################################################
class SlackDownload(ProjectDEPRECATED, Base):
    __tablename__ = "slack_downloads"
    __table_args__ = (
        UniqueConstraint(
            "source",
            "agent_id",
            "originating_object_id",
            "workspace_id",
            "download_id",
            name="slack_downloads_unique_constraint",
        ),
        {
            "comment": "Parsed downloads from a 'slack-downloads' file or Seatbelt json",
        },
    )

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique row identifier for each Slack download entry",
    )
    agent_id: Mapped[str] = mapped_column(
        Text, nullable=False, comment="C2 identifier of the agent that collected the data"
    )
    originating_object_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(), nullable=False, comment="Nemesis file UUID if this entry originated from a file"
    )
    username: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Username extracted from file path, if applicable"
    )
    workspace_id: Mapped[str] = mapped_column(Text, nullable=False, comment="Extracted from slack-downloads")
    download_id: Mapped[str] = mapped_column(Text, nullable=False, comment="Extracted from slack-downloads")
    team_id: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Extracted from slack-downloads")
    user_id: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Extracted from slack-downloads")
    url: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Extracted from slack-downloads")
    download_path: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Extracted from slack-downloads")
    download_state: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Extracted from slack-downloads")
    start_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Extracted from slack-downloads"
    )
    end_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Extracted from slack-downloads"
    )


class SlackWorkspace(ProjectDEPRECATED, Base):
    __tablename__ = "slack_workspaces"
    __table_args__ = (
        UniqueConstraint(
            "source",
            "agent_id",
            "originating_object_id",
            "workspace_id",
            "workspace_domain",
            "workspace_name",
            name="slack_workspaces_unique_constraint",
        ),
        {
            "comment": "Parsed workspaces from a 'slack-workspaces' file or Seatbelt json",
        },
    )

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique row identifier for each Slack download entry",
    )
    agent_id: Mapped[str] = mapped_column(
        Text, nullable=False, comment="C2 identifier of the agent that collected the data"
    )
    originating_object_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(), nullable=True, comment="Nemesis file UUID if this entry originated from a file"
    )
    username: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Username extracted from file path, if applicable"
    )
    workspace_id: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Extracted from slack-workspaces")
    workspace_domain: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Extracted from slack-workspaces")
    workspace_name: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Extracted from slack-workspaces")
    workspace_icon_url: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Extracted from slack-workspaces"
    )


########################################################################
# Authentication/Credential data
########################################################################
class ExtractedHash(ProjectDEPRECATED, Base):
    __tablename__ = "extracted_hashes"
    __table_args__ = (
        UniqueConstraint(
            "timestamp", "originating_object_id", "hash_value_md5_hash", name="extracted_hashes_unique_constraint"
        ),
        {
            "comment": "Extracted hashes from various sources (e.g., encrypted files/documents)",
        },
    )

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique identifier",
    )
    agent_id: Mapped[str] = mapped_column(Text, nullable=False)
    originating_object_id: Mapped[UUID | None] = mapped_column(
        sqlalchemy.UUID(), nullable=True, comment="Nemesis file UUID if the hash was carved from a file"
    )
    hash_type: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Type of hash")
    hash_value: Mapped[str] = mapped_column(Text, nullable=False, comment="Value of the extracted hash")
    hashcat_formatted_value: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Hashcat-formatted hash value"
    )
    jtr_formatted_value: Mapped[str | None] = mapped_column(Text, nullable=True, comment="JTR-formatted hash value")
    is_cracked: Mapped[bool | None] = mapped_column(Boolean, nullable=True, comment="True if the hash has been cracked")
    checked_against_top_passwords: Mapped[bool | None] = mapped_column(
        Boolean, nullable=True, comment="True if checked against top passwords"
    )
    is_submitted_to_cracker: Mapped[bool | None] = mapped_column(
        Boolean, nullable=True, comment="True if submitted to a cracker"
    )
    cracker_submission_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Time the hash was submitted to a cracker"
    )
    cracker_cracked_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Time the hash was cracked"
    )
    plaintext_value: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Plaintext value if the hash has been cracked"
    )
    hash_value_md5_hash: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        Computed("MD5(hash_value)::uuid"),
        nullable=False,
        comment="MD5 hash of the hash value. Used in the unique constraint due to hashes potentially being too long for constraints",
    )


class AuthenticationData(ProjectDEPRECATED, Base):
    __tablename__ = "authentication_data"
    __table_args__ = {
        "comment": "Authentication data submitted to the API or surfaced by Nemesis",
    }

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique identifier",
    )
    agent_id: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[str | None] = mapped_column(Text, nullable=True)
    type: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_file: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    username: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    originating_object_id: Mapped[UUID | None] = mapped_column(sqlalchemy.UUID(), nullable=True)


########################################################################
# DEPRECATED: Host/Agent info
########################################################################
class HostDEPRECATED(ProjectDEPRECATED, Base):
    __tablename__ = "hosts_deprecated"
    __table_args__ = (UniqueConstraint("hostname", name="hosts_unique_constraint"),)

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique identifier",
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    os_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    windows_major_version: Mapped[float | None] = mapped_column(Numeric(9, 1), nullable=True)
    windows_build: Mapped[str | None] = mapped_column(Text, nullable=True)
    windows_release: Mapped[str | None] = mapped_column(Text, nullable=True)
    windows_domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    linux_kernel_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    linux_distributor: Mapped[str | None] = mapped_column(Text, nullable=True)
    linux_release: Mapped[str | None] = mapped_column(Text, nullable=True)
    agent_ids: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)


class AgentsDEPRECATED(ProjectDEPRECATED, Base):
    __tablename__ = "agents_deprecated"
    __table_args__ = (
        UniqueConstraint("agent_id", "agent_type", name="agents_unique_constraint"),
        {"comment": "Tracks agents that have connected to the server"},
    )

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        server_default=text("gen_random_uuid()"),
        nullable=False,
        comment="Unique identifier",
    )
    agent_id: Mapped[str] = mapped_column(
        Text, primary_key=True, nullable=False, comment="ID from Cobalt Strike/Mythic/etc."
    )
    host_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("hosts_deprecated.id"), nullable=True, comment="Reference to host the agent is running on"
    )
    agent_type: Mapped[str] = mapped_column(Text, nullable=False, comment="Type of the agent")
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Timestamp when the agent was first seen"
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Timestamp when the agent was last seen"
    )
    is_alive: Mapped[bool | None] = mapped_column(
        Boolean, nullable=True, comment="True if the agent is currently alive"
    )
    arch: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Architecture of the agent's system")
    process_name: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Name of the process the agent is running as"
    )
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True, comment="Process ID of the agent process")
    process_username: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Username under which the agent process is running"
    )


########################################################################
# Triage/Analysis
########################################################################
# TODO: Update triage/notes to use unique_db_id in new schema, use a join table instead of tablename
class Triage(Base):
    __tablename__ = "triage"
    __table_args__ = {"comment": "Tracks objects in the DB that have been triaged by operator input"}

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(),
        nullable=False,
        primary_key=True,
        comment="Unique DB ID of the object that has been triaged",
    )
    table_name: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Table name the unique_db_id originates from"
    )
    modification_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Last time the field was modified"
    )
    expiration: Mapped[datetime.date] = mapped_column(
        Date, nullable=False, comment="Date when the entry should be wiped from the database"
    )
    operator: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Name of the operator making the change")
    value: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Value indicating usefulness (Useful/Not Useful/Unknown) or not set"
    )


class Notes(Base):
    __tablename__ = "notes"
    __table_args__ = {"comment": "Tracks operator notes when they triage a piece of data"}

    unique_db_id: Mapped[UUID] = mapped_column(
        sqlalchemy.UUID(), primary_key=True, nullable=False, comment="Unique DB ID of the object that has a note added"
    )
    table_name: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Table name the unique_db_id originates from"
    )
    modification_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, comment="Last time the field was modified"
    )
    expiration: Mapped[datetime.date] = mapped_column(
        Date, nullable=False, comment="Date when the entry should be wiped from the database"
    )
    operator: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Name of the operator making the change")
    value: Mapped[str | None] = mapped_column(Text, nullable=True, comment="Text of the note left by an operator")

