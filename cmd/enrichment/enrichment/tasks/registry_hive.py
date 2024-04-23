# Standard Libraries
import asyncio
import time
import uuid

# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
import structlog
from enrichment.lib.registry import get_registry_values_from_hive
from nemesiscommon.messaging import MessageQueueConsumerInterface, MessageQueueProducerInterface
from nemesiscommon.storage import StorageInterface
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger(module=__name__)


class RegistryHive(TaskInterface):
    """
    Class responsible for parsing raw registry hives and emitting
    registry value messages after filtering.
    """

    storage: StorageInterface
    registry_value_batch_size: int

    # Queues
    in_q_filedataenriched: MessageQueueConsumerInterface
    out_q_registryvalue: MessageQueueProducerInterface

    def __init__(
        self,
        storage: StorageInterface,
        registry_value_batch_size: int,
        in_q_filedataenriched: MessageQueueConsumerInterface,
        out_q_registryvalue: MessageQueueProducerInterface,
    ):
        self.storage = storage

        self.in_q_filedataenriched = in_q_filedataenriched
        self.out_q_registryvalue = out_q_registryvalue

        # number of registry values to include in a single RegistryValueIngestionMessage message
        self.registry_value_batch_size = registry_value_batch_size

    async def run(self) -> None:
        await logger.ainfo("Starting the Registry Hive service")

        await asyncio.gather(
            self.in_q_filedataenriched.Read(self.handle_file_data_enriched),  # type: ignore
        )
        await asyncio.Future()

    async def handle_file_data_enriched(self, q_msg: pb.FileDataEnrichedMessage) -> None:
        await self.process_file_data_enriched(q_msg)

    @aio.time(Summary("process_file_data_enriched_reg_hive", "Time spent processing a file_data_enriched topic"))  # type: ignore
    async def process_file_data_enriched(self, event: pb.FileDataEnrichedMessage):
        for data in event.data:
            if data.magic_type.startswith("MS Windows registry file"):
                try:
                    with await self.storage.download(uuid.UUID(data.object_id)) as temp_file:
                        # extract out any keys from a hive we can and submit them to the registry_value queue
                        registry_message = pb.RegistryValueIngestionMessage()
                        registry_message.metadata.CopyFrom(event.metadata)
                        start = time.time()
                        value_counter = 0
                        total_values = 0

                        async for reg_entry in get_registry_values_from_hive(temp_file.name):
                            if value_counter == self.registry_value_batch_size:
                                # include up to self.registry_value_batch_size values in the registry message
                                await self.out_q_registryvalue.Send(registry_message.SerializePartialToString())
                                del registry_message.data[:]
                            registry_message.data.extend([reg_entry])
                            value_counter += 1
                            total_values += 1

                        # send what's left
                        if len(registry_message.data) > 0:
                            await self.out_q_registryvalue.Send(registry_message.SerializePartialToString())

                        await logger.ainfo(
                            f"Registry hive values ({total_values}) for {data.name} extracted in {time.time() - start} seconds, emitting RegistryValueIngestionMessage"
                        )
                except Exception as e:
                    await logger.aexception(e, message="Exception in process_file_data_enriched")
