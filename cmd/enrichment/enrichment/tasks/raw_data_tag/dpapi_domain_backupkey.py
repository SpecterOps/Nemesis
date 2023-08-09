# Standard Libraries
import base64
import json
import os
import uuid
from typing import Dict

# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
import structlog
from nemesiscommon.messaging import MessageQueueProducerInterface
from nemesiscommon.storage import StorageInterface

logger = structlog.get_logger(__name__)


class dpapi_domain_backupkey:
    dpapi_domain_backupkey_q_out: MessageQueueProducerInterface
    storage: StorageInterface
    tasks_set = set()

    def __init__(
        self,
        dpapi_domain_backupkey_q_out: MessageQueueProducerInterface,
        storage: StorageInterface,
    ):
        self.dpapi_domain_backupkey_q_out = dpapi_domain_backupkey_q_out
        self.storage = storage

    async def process(self, event: pb.RawDataIngestion, metadata: pb.Metadata):
        if not event.is_file:
            await logger.awarning("Received a DPAPI backupkey file that is not a file", metadata=metadata)
            return

        # When the raw_data record has is_file=True, the "event.data" field is the file object UUID
        filename = uuid.UUID(event.data)

        with await self.storage.download(filename) as temp_file:
            # get temp file size
            size = os.path.getsize(temp_file.name)
            if size == 0:
                await logger.aerror("Received a DPAPI backupkey file that is empty", metadata=metadata)
                return
            elif size < 2:
                await logger.aerror("Received a DPAPI backupkey file that is less than 2 bytes, and therefore invalid JSON", metadata=metadata)
                return

            with open(temp_file.name, "rb") as f:
                domain_backupkey_msg = await self.parse_json(f.read(), metadata)
                await self.dpapi_domain_backupkey_q_out.Send(domain_backupkey_msg.SerializeToString())

    async def parse_json(self, text: bytes, metadata: pb.Metadata) -> pb.DpapiDomainBackupkeyMessage:
        domain_backupkey: Dict[str, str] = json.loads(text)

        if "domain_backupkey_guid" not in domain_backupkey:
            raise ValueError("Received DpapiDomainBackupkeyMessage, but domain_backupkey_guid not found in JSON")

        if "domain_backupkey_b64" not in domain_backupkey:
            raise ValueError("Received DpapiDomainBackupkeyMessage, but domain_backupkey_b64 not found in JSON")

        domain_backupkey_guid = domain_backupkey["domain_backupkey_guid"]
        domain_controller = domain_backupkey["domain_controller"] if "domain_controller" in domain_backupkey else ""
        domain_backupkey_bytes = base64.b64decode(domain_backupkey["domain_backupkey_b64"])

        domain_backupkey_msg = pb.DpapiDomainBackupkeyMessage()
        domain_backupkey_data = pb.DpapiDomainBackupkey(
            domain_controller=domain_controller,
            domain_backupkey_guid=domain_backupkey_guid,
            domain_backupkey_bytes=domain_backupkey_bytes,
        )

        domain_backupkey_msg.metadata.CopyFrom(metadata)
        domain_backupkey_msg.data.extend([domain_backupkey_data])

        return domain_backupkey_msg
