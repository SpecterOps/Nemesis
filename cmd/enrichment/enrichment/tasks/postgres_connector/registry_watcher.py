# Standard Libraries
import base64
import re
from typing import Dict, List, Set

# 3rd Party Libraries
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
import structlog
from enrichment.lib.nemesis_db import NemesisDb, RegistryObject, ServiceColumn
from enrichment.tasks.postgres_connector.registry_path_utils import normalize_registry_path, parse_next_subkey
from nemesiscommon.messaging import MessageQueueProducerInterface
from winacl.dtyp.ace import ACCESS_ALLOWED_CALLBACK_ACE
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

logger = structlog.get_logger(module=__name__)


class RegistryWatcher:
    db: NemesisDb
    out_q_dpapiblob: MessageQueueProducerInterface

    # Constants
    SERVICES_REGISTRY_PATH_REGEX: re.Pattern = re.compile(
        r"^hklm[:]?\\system\\(currentcontrolset|controlset001|controlset002)\\services\\", re.IGNORECASE
    )
    SERVICES_REGISTRY_PATH_MIN_LEN: int = len("hklm\\system\\controlset001\\services\\")
    SERVICE_REG_VALUE_TO_COLUMN: Dict[str, ServiceColumn] = {
        "displayname": ServiceColumn.DISPLAY_NAME,
        "description": ServiceColumn.DESCRIPTION,
        "imagepath": ServiceColumn.BINARY_PATH,
        "objectname": ServiceColumn.USERNAME,
        "type": ServiceColumn.SERVICE_TYPE,
        "start": ServiceColumn.START_TYPE,
    }
    SERVICES_ROOT_VALUE_NAMES: Set[str] = set(SERVICE_REG_VALUE_TO_COLUMN.keys())
    SERVICE_PARAMETER_VALUE_NAMES: List[str] = ["servicedll", "servicemain"]
    SERVICE_SECURITY_VALUE_NAMES: List[str] = [
        "security",
    ]

    def __init__(self, db: NemesisDb, out_q_dpapiblob: MessageQueueProducerInterface) -> None:
        self.db = db
        self.out_q_dpapiblob = out_q_dpapiblob

    async def process_registry_value(self, event: pb.RegistryValueIngestionMessage) -> None:
        metadata = event.metadata

        for d in event.data:
            normalized = await self.normalize_registry_value(d)

            unique_db_id = await self.save_reg_value_to_db(metadata, normalized)

            if d.tags and "dpapi_value" in d.tags:
                # if the registry value is tagged as containing DPAPI data carve it
                try:
                    raw_bytes = base64.b64decode(d.value)
                    carved = await helpers.carve_dpapi_blobs_from_reg_key(raw_bytes, unique_db_id, metadata)
                    if carved is not None:
                        (dpapi_blob_ids, dpapi_blob_messages) = carved
                        # publish any carved DPAPI blobs to the queue
                        for dpapi_blob_message in dpapi_blob_messages:
                            await self.out_q_dpapiblob.Send(dpapi_blob_message.SerializeToString())
                except Exception as e:
                    logger.exception(
                        "Carving DPAPI blob from registry key failed",
                        e,
                        key=d.key,
                        value_name=d.value_name,
                        unique_db_id=unique_db_id,
                        project=metadata.project,
                        agent_id=metadata.agent_id,
                    )
            # TODO: Need to provide support for services specifying info in both key's default values
            # or in in registry values. For example, an SDDL can be specified in a
            # or "Services\<service>\Security ! (Default)"" or "Services\<service> ! Security"
            await self.build_service_from_registry(metadata, normalized)

    async def normalize_registry_value(self, r: pb.RegistryValueIngestion) -> pb.RegistryValueIngestion:
        """Normalizes a registry value"""

        # Normalize the key path
        r.key = normalize_registry_path(r.key)
        return r

    async def save_reg_value_to_db(self, m: pb.Metadata, r: pb.RegistryValueIngestion) -> str:
        """Saves a registry value to the database

        Args:
            metadata (pb.Metadata): Protobuf object containing the metadata.
            r (pb.RegistryValueIngestion): Protobuf object containing the registry value.
        """
        reg_data = RegistryObject(
            m.agent_id,
            m.project,
            m.source,
            m.timestamp.ToDatetime(),
            m.expiration.ToDatetime(),
            r.key,
            r.value_kind,
            r.sddl,
            r.value_name,
            r.value,
            r.tags,
        )

        unique_db_id = await self.db.add_registry_object(reg_data)
        return unique_db_id

    async def build_service_from_registry(self, metadata: pb.Metadata, data: pb.RegistryValueIngestion) -> None:
        keyAbsPath = data.key

        if len(keyAbsPath) <= self.SERVICES_REGISTRY_PATH_MIN_LEN:
            return

        regex_match = self.SERVICES_REGISTRY_PATH_REGEX.match(keyAbsPath)
        if not regex_match:
            return

        if data.value_name:
            value_name = data.value_name.lower()
        else:
            value_name = None

        value = data.value

        remaining_path = keyAbsPath[regex_match.end() :]
        service_name, remaining_path = parse_next_subkey(remaining_path)

        if remaining_path:
            subkey, remaining_path = parse_next_subkey(remaining_path)
        else:
            subkey = None

        if not value_name:
            await self.db.add_service(metadata, service_name)
            return

        if not subkey:
            # We're in the service's root key (e.g. "Services\<service>\")
            await self.handle_service_root_key(metadata, service_name, value_name, value)
        else:
            if remaining_path:
                # If we're in a subkey that we don't support yet (e.g. "Services\<service>\Parameters\Subkey")
                return

            if subkey.lower() == "parameters":
                await self.handle_service_parameters_key(metadata, service_name, value_name, value)
            if subkey.lower() == "security":
                await self.handle_service_security_key(metadata, service_name, value_name, value)

    def convert_raw_security_descriptor_to_sddl(self, sd_bytes: bytes) -> str:
        """
        Converts raw security descritor bytes to a SDDL string.
        """
        return SECURITY_DESCRIPTOR.from_bytes(sd_bytes).to_sddl()

    async def handle_service_root_key(
        self, metadata: pb.Metadata, service_name: str, value_name: str, value: str
    ) -> None:
        """Handles ingestion of values from a service's root registry key("HKLM\\SYSTEM\\CurrentControlSet\\Services\\SERVICE_NAME").

        Args:
            metadata (pb.Metadata): The metadata about the registy value.
            service_name (str): Name of the service associated with the parameters key.
            value_name (str): Name of the registry value.
            value (str): Value of the registry value.
        """
        value_name_lower = value_name.lower()
        if value_name_lower not in self.SERVICE_REG_VALUE_TO_COLUMN:
            return

        column: ServiceColumn = self.SERVICE_REG_VALUE_TO_COLUMN[value_name_lower]

        match value_name_lower:
            case "imagepath":
                await self.db.add_service_property(metadata, service_name, column, value)
                command_line = helpers.extract_binary_path(value)
                if command_line:
                    await self.db.add_service_property(metadata, service_name, ServiceColumn.COMMAND_LINE, command_line)

            case "start":
                await self.db.add_service_property(metadata, service_name, column, int(value))
            case "type":
                await self.db.add_service_property(metadata, service_name, column, int(value))
            case _:
                if value_name_lower in self.SERVICES_ROOT_VALUE_NAMES:
                    await self.db.add_service_property(metadata, service_name, column, value)

    async def handle_service_parameters_key(
        self, metadata: pb.Metadata, service_name: str, value_name: str, value: str
    ) -> None:
        """Handles ingestion of values from the "Services\\SERVICE_NAME\\Parameters" registry key.

        Args:
            metadata (pb.Metadata): The metadata about the registy value.
            service_name (str): Name of the service associated with the parameters key.
            value_name (str): Name of the registry value.
            value (str): Value of the registry value.
        """
        if value_name not in self.SERVICE_PARAMETER_VALUE_NAMES:
            return

        if value_name == "servicedll":
            await self.db.add_service_property(metadata, service_name, ServiceColumn.SERVICE_DLL_PATH, value)
        elif value_name == "servicemain":
            await self.db.add_service_property(metadata, service_name, ServiceColumn.SERVICE_DLL_ENTRYPOINT, value)

    async def handle_service_security_key(
        self, metadata: pb.Metadata, service_name: str, value_name: str, value: str
    ) -> None:
        """Handles ingestion of values from the "Services\\SERVICE_NAME\\Security" registry key.

        Args:
            metadata (pb.Metadata): The metadata about the registy value.
            service_name (str): Name of the service associated with the parameters key.
            value_name (str): Name of the registry value.
            value (str): Value of the registry value.
        """
        if value_name not in self.SERVICE_SECURITY_VALUE_NAMES:
            return

        try:
            sec_desc_bytes = base64.b64decode(value)
            sddl = self.convert_raw_security_descriptor_to_sddl(sec_desc_bytes)
            await self.db.add_service_property(metadata, service_name, ServiceColumn.SDDL, sddl)
        except AttributeError as e:
            if e.name == "to_sddl" and type(e.obj) == ACCESS_ALLOWED_CALLBACK_ACE:
                logger.warning(
                    "Data loss due to bytes-to-SDDL conversion failing due to a known bug: there's an ACCESS_ALLOWED_CALLBACK_ACE in the security descriptor (see https://github.com/skelsec/winacl/issues/10)",
                    project=metadata.project,
                    agent_id=metadata.agent_id,
                    service=service_name,
                )
            else:
                logger.exception(
                    "Bytes to SDDL conversion failed",
                    e,
                    project=metadata.project,
                    agent_id=metadata.agent_id,
                    service=service_name,
                    base64_bytes=value,
                )
