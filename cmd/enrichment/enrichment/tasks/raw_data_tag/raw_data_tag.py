# Standard Libraries
import asyncio
import time
import uuid
from typing import Callable

# 3rd Party Libraries
import enrichment.lib.nemesis_db as db
import nemesispb.nemesis_pb2 as pb
import structlog
from enrichment.lib.nemesis_db import NemesisDb
from enrichment.lib.registry import include_registry_value
from enrichment.tasks.raw_data_tag.bof_reg_collect_parser import \
    parse_serialized_reg_data
from enrichment.tasks.raw_data_tag.dpapi_domain_backupkey import \
    dpapi_domain_backupkey
from enrichment.tasks.raw_data_tag.seatbelt_json import seatbelt_json
from google.protobuf.json_format import ParseDict
from nemesiscommon.messaging import (MessageQueueConsumerInterface,
                                     MessageQueueProducerInterface)
from nemesiscommon.storage import StorageInterface
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger()


class RawDataTag(TaskInterface):
    """
    Class responsible for processing the "tags" field in RawDataIngestionMessage messages.
    """

    storage: StorageInterface
    db: NemesisDb
    in_q_rawdata: MessageQueueConsumerInterface
    reg_value_q: MessageQueueProducerInterface
    file_info_q: MessageQueueProducerInterface
    service_output_q: MessageQueueProducerInterface
    named_pipe_q: MessageQueueProducerInterface
    dpapi_domain_backupkey_q_out: MessageQueueProducerInterface
    out_q_network_connection: MessageQueueProducerInterface
    RAW_DATA_HANDLER_MAP = {}

    def __init__(
        self,
        storage: StorageInterface,
        db: NemesisDb,
        in_q_rawdata: MessageQueueConsumerInterface,
        out_q_dpapi_domain_backupkey: MessageQueueProducerInterface,
        out_q_file_info: MessageQueueProducerInterface,
        out_q_reg_value: MessageQueueProducerInterface,
        out_q_service: MessageQueueProducerInterface,
        out_q_named_pipe: MessageQueueProducerInterface,
        out_q_network_connection: MessageQueueProducerInterface,
    ):
        self.in_q_rawdata = in_q_rawdata

        self.TAG_HANDLER_MAP: dict[str, Callable] = {
            "bof_reg_collect": self.process_bof_reg_collect,
            "seatbelt_json": self.process_seatbelt_raw_data,
            "dpapi_domain_backupkey": self.process_dpapi_domain_backupkey,
        }
        self.storage = storage
        self.db = db

        self.dpapi_domain_backupkey_q_out = out_q_dpapi_domain_backupkey
        self.file_info_q = out_q_file_info
        self.reg_value_q = out_q_reg_value
        self.service_output_q = out_q_service
        self.named_pipe_q = out_q_named_pipe
        self.network_connection_q = out_q_network_connection

    async def run(self) -> None:
        await self.in_q_rawdata.Read(self.process_message)  # type: ignore
        await asyncio.Future()

    async def process_message(self, event: pb.RawDataIngestionMessage) -> None:
        """Processes tags in RawDataIngestionMessage messages.

        Args:
            event (pb.RawDataIngestionMessage): RawDataIngestionMessage to process.
        """

        if not len(event.data) > 0:
            return

        for data in event.data:
            if not data.tags:
                continue

            for tag in data.tags:
                if tag in self.TAG_HANDLER_MAP:
                    structlog.contextvars.bind_contextvars(
                        tag=tag,
                        message_id=event.metadata.message_id,
                    )
                    start_time = time.perf_counter()
                    await logger.ainfo("Processing raw_data")

                    await self.ensure_project_exists(event.metadata)
                    await self.TAG_HANDLER_MAP[tag](data, event.metadata)

                    end_time = time.perf_counter()
                    await logger.ainfo(
                        "Finished processing tag",
                        total_time=(end_time - start_time),
                    )

    async def ensure_project_exists(self, metadata: pb.Metadata):
        """Ensures a project exists in the database.

        Args:
            metadata (pb.Metadata): Metadata for the project.
        """
        # TODO: Create a cache of projects stored in memory so we don't hit the DB for every event
        p = db.Project(
            metadata.project,
            metadata.timestamp.ToDatetime(),
            metadata.expiration.ToDatetime(),
        )
        await self.db.add_project(p)

    @aio.time(Summary("process_bof_reg_collect", "Time spent processing bof_reg_collect"))  # type: ignore
    async def process_bof_reg_collect(self, event: pb.RawDataIngestion, metadata: pb.Metadata):
        """Processes a raw_data message associated with a bof_reg_collect file.

        Args:
            event (pb.RawDataIngestion): RawDataIngestion event to process.
            metadata (pb.Metadata): Metadata for the event.
        """

        if not event.is_file:
            await logger.awarning("Received a bof_reg_collect file that is not a file", metadata=metadata)
            return

        # When the raw_data record has is_file=True, the "data" field is the file object UUID
        filename = uuid.UUID(event.data)

        with await self.storage.download(filename) as temp_file:
            msg = pb.RegistryValueIngestionMessage()
            msg.metadata.CopyFrom(metadata)

            keys = [
                {"key": key.path, "value_name": key.key, "value": str(key.value), "value_kind": key.type_}
                for key in parse_serialized_reg_data(temp_file.name)
                if include_registry_value(key=key.path, value_name=key.key, value_kind=key.type_, value=key.value)
            ]
            for key in keys:
                obj = pb.RegistryValueIngestion()
                msg_fmt = ParseDict(key, obj)
                msg.data.append(msg_fmt)

            await self.reg_value_q.Send(msg.SerializeToString())

    @aio.time(Summary("process_tag_seatbelt_json", "Time spent processing Seatbelt JSON"))  # type: ignore
    async def process_seatbelt_raw_data(self, event: pb.RawDataIngestion, metadata: pb.Metadata):
        """Processes a raw_data message associated with a Seatbelt NDJSON file.

        Args:
            event (pb.RawDataIngestion): RawDataIngestion event to process.
            metadata (pb.Metadata): Metadata for the event.
        """
        seatbelt = seatbelt_json(
            self.db,
            self.storage,
            self.file_info_q,
            self.reg_value_q,
            self.service_output_q,
            self.named_pipe_q,
            self.network_connection_q,
        )
        await seatbelt.process(event, metadata)

    @aio.time(Summary("process_tag_dpapi_domain_backupkey", "Time spent processing DPAPI domain backup keys"))  # type: ignore
    async def process_dpapi_domain_backupkey(self, event: pb.RawDataIngestion, metadata: pb.Metadata):
        """Processes a raw_data message associated with a DPAPI domain backupkey.

        Args:
            event (pb.RawDataIngestion): RawDataIngestion event to process.
            metadata (pb.Metadata): Metadata for the event.
        """
        dpapi = dpapi_domain_backupkey(
            dpapi_domain_backupkey_q_out=self.dpapi_domain_backupkey_q_out,
            storage=self.storage,
        )
        await dpapi.process(event, metadata)
