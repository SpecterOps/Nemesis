# Standard Libraries
import asyncio
import uuid
from typing import Callable, Coroutine

# 3rd Party Libraries
import enrichment.lib.nemesis_db as db
import jsonlines
import nemesispb.nemesis_pb2 as pb
import structlog
from enrichment.lib.nemesis_db import Metadata, NemesisDb
from enrichment.tasks.raw_data_tag.seatbelt_datatypes import (
    SeatbeltBaseDTO,
    SeatbeltDtoTypes,
    SeatbeltFileInfo,
    SeatbeltNamedPipe,
    SeatbeltOSInfo,
    SeatbeltRegistryValue,
    SeatbeltService,
    SeatbeltTcpConnection,
    SeatbeltUdpConnection,
    parse_seatbelt_date,
)
from nemesiscommon.messaging import MessageQueueProducerInterface
from nemesiscommon.storage import StorageInterface

logger = structlog.get_logger(__name__)


class seatbelt_json:
    db: NemesisDb
    storage: StorageInterface
    file_info_q: MessageQueueProducerInterface
    reg_value_q: MessageQueueProducerInterface
    service_output_q: MessageQueueProducerInterface
    named_pipe_q: MessageQueueProducerInterface
    network_connection_q: MessageQueueProducerInterface
    tasks_set = set()

    def __init__(
        self,
        db: NemesisDb,
        storage: StorageInterface,
        file_info_q: MessageQueueProducerInterface,
        reg_value_q: MessageQueueProducerInterface,
        service_output_q: MessageQueueProducerInterface,
        named_pipe_q: MessageQueueProducerInterface,
        network_connection_q: MessageQueueProducerInterface,
    ):
        self.db = db
        self.storage = storage
        self.file_info_q = file_info_q
        self.reg_value_q = reg_value_q
        self.service_output_q = service_output_q
        self.named_pipe_q = named_pipe_q
        self.network_connection_q = network_connection_q

    async def create_task(self, func: Coroutine) -> None:
        task = asyncio.create_task(func)
        self.tasks_set.add(task)
        task.add_done_callback(self.tasks_set.discard)

    async def process(self, event: pb.RawDataIngestion, metadata: pb.Metadata) -> None:
        """Processes a raw_data message associated with a Seatbelt NDJSON file.

        Args:
            event (pb.RawDataIngestion): RawDataIngestion event to process.
            metadata (pb.Metadata): Metadata for the event.
        """

        if not event.is_file:
            await logger.awarning("Received a Seatbelt file that is not a file", metadata=metadata)
            return

        # Create seatbelt taskgroup
        self.reg_msg = pb.RegistryValueIngestionMessage()
        self.reg_msg.metadata.CopyFrom(metadata)

        # When the raw_data record has is_file=True, the "data" field is the file object UUID
        filename = uuid.UUID(event.data)

        with await self.storage.download(filename) as temp_file:
            await self.read_ndjson_file(
                temp_file.name,
                self.parse_json,
                metadata=metadata,
            )

        # Send outstanding registry messages
        if len(self.reg_msg.data) > 0:
            await self.create_task(self.reg_value_q.Send(self.reg_msg.SerializeToString()))
            del self.reg_msg.data[:]  # Clear the list

        # wait for all outstanding tasks to complete
        await logger.ainfo("Waiting for all tasks to complete")
        await asyncio.gather(*self.tasks_set)

    async def read_ndjson_file(self, filename: str, callback: Callable, **kwargs) -> None:
        """Loads a Seatbelt new-line deliniated JSON file and calls the callback function for each DTO entry.

        Args:
            filename (str): Path to the new-line deliniated Seatbelt JSON file
            metadata (pb.Metadata): The metadata for the raw_data event
            callback (function): Callback function to call for each entry in the file. The callback should accept two arguments: the SeatbeltBaseDTO object and the metadata.
        """
        with jsonlines.open(filename) as reader:
            for line in reader:
                await callback(line, **kwargs)

    async def parse_json(self, line, metadata: pb.Metadata):
        obj = SeatbeltBaseDTO.from_dict(line)
        await self.process_dto(obj, metadata)

    async def process_dto(self, obj: SeatbeltBaseDTO, metadata: pb.Metadata):
        """Processes a SeatbeltBaseDTO object and sends the appropriate protobuf message to the appropriate queue.
        This function is called for each entry in the Seatbelt JSON file.

        Args:
            obj (SeatbeltBaseDTO): The SeatbeltBaseDTO object to process
            metadata (pb.Metadata): The metadata for the raw_data event
        """

        if obj.Type == SeatbeltDtoTypes.REGISTRY_VALUE.value:
            reg_dto = SeatbeltRegistryValue.from_dict(obj.Data)
            reg_pb = reg_dto.to_protobuf()

            self.reg_msg.data.append(reg_pb)

            if len(self.reg_msg.data) >= 100:
                await self.create_task(self.reg_value_q.Send(self.reg_msg.SerializeToString()))
                del self.reg_msg.data[:]  # Clear the list

        elif obj.Type == SeatbeltDtoTypes.FILE_INFO.value:
            file_dto = SeatbeltFileInfo.from_dict(obj.Data)
            file_pb = file_dto.to_protobuf()

            msg = pb.FileInformationIngestionMessage()
            msg.metadata.CopyFrom(metadata)
            msg.data.append(file_pb)

            await self.create_task(self.file_info_q.Send(msg.SerializeToString()))

        elif obj.Type == SeatbeltDtoTypes.NAMED_PIPE.value:
            named_pipe_dto = SeatbeltNamedPipe.from_dict(obj.Data)
            named_pipe_pb = named_pipe_dto.to_protobuf()

            msg = pb.NamedPipeIngestionMessage()
            msg.metadata.CopyFrom(metadata)
            msg.data.append(named_pipe_pb)

            await self.create_task(self.named_pipe_q.Send(msg.SerializeToString()))

        elif obj.Type == SeatbeltDtoTypes.TCP_CONNECTION.value:
            tcp_connection_dto = SeatbeltTcpConnection.from_dict(obj.Data)
            tcp_connection_pb = tcp_connection_dto.to_protobuf()

            msg = pb.NetworkConnectionIngestionMessage()
            msg.metadata.CopyFrom(metadata)
            msg.data.append(tcp_connection_pb)

            await self.create_task(self.network_connection_q.Send(msg.SerializeToString()))

        elif obj.Type == SeatbeltDtoTypes.UDP_CONNECTION.value:
            udp_connection_dto = SeatbeltUdpConnection.from_dict(obj.Data)
            udp_connection_pb = udp_connection_dto.to_protobuf()

            msg = pb.NetworkConnectionIngestionMessage()
            msg.metadata.CopyFrom(metadata)
            msg.data.append(udp_connection_pb)

            await self.create_task(self.network_connection_q.Send(msg.SerializeToString()))

        elif obj.Type == SeatbeltDtoTypes.OS_INFO.value:
            osinfo_dto = SeatbeltOSInfo.from_dict(obj.Data)
            m = Metadata(
                metadata.agent_id,
                metadata.project,
                metadata.source,
                metadata.timestamp.ToDatetime(),
                metadata.expiration.ToDatetime(),
            )
            h = db.HostInfo.from_seatbelt_dto(osinfo_dto, m)

            # TODO: we have to build a protobuf if we want to emit to the queue instead of the DB
            await self.create_task(self.db.add_host_info(h))

        elif obj.Type == SeatbeltDtoTypes.SLACK_DOWNLOADS.value:
            username = obj.Data["UserName"]
            for download in obj.Data["Downloads"]:
                try:
                    seatbelt_slack_download = db.SlackDownload(
                        metadata.agent_id,
                        metadata.project,
                        metadata.source,
                        metadata.timestamp.ToDatetime(),
                        metadata.expiration.ToDatetime(),
                        username,
                        download["TeamID"],
                        download["UserID"],
                        download["DownloadPath"].replace("\\", "/"),
                        parse_seatbelt_date(download["StartTime"]),
                    )
                    # TODO: we have to build a protobuf if we want to emit to the queue instead of the DB
                    await self.create_task(self.db.add_slack_download(seatbelt_slack_download))
                except Exception as e:
                    await logger.aerror("Error parsing a Seatbelt Slack download line", error=e)

        elif obj.Type == SeatbeltDtoTypes.SLACK_WORKSPACES.value:
            username = obj.Data["UserName"]
            for workspace in obj.Data["Workspaces"]:
                try:
                    seatbelt_slack_workspace = db.SlackWorkspace(
                        metadata.agent_id,
                        metadata.project,
                        metadata.source,
                        metadata.timestamp.ToDatetime(),
                        metadata.expiration.ToDatetime(),
                        username,
                        workspace["Name"],
                        workspace["Domain"],
                        workspace["ID"],
                    )
                    # TODO: we have to build a protobuf if we want to emit to the queue instead of the DB
                    await self.create_task(self.db.add_slack_workspace(seatbelt_slack_workspace))
                except Exception as e:
                    await logger.aerror("Error parsing a Seatbelt Slack workspace line", error=e)

        elif obj.Type == SeatbeltDtoTypes.SERVICE_INFO.value:
            service_dto = SeatbeltService.from_dict(obj.Data)
            service_pb = service_dto.to_protobuf()

            msg = pb.ServiceIngestionMessage()
            msg.metadata.CopyFrom(metadata)
            msg.data.append(service_pb)

            await self.service_output_q.Send(msg.SerializeToString())

            # if there's non-null file information, also emit that
            if "BinaryPath" in obj.Data and obj.Data["BinaryPath"] is not None:
                file_info_pb = pb.FileInformationIngestion()
                file_info_pb.path = obj.Data["BinaryPath"]

                if "BinaryPathSDDL" in obj.Data and obj.Data["BinaryPathSDDL"] is not None:
                    file_info_pb.sddl = obj.Data["BinaryPathSDDL"]

                version_info = ""

                if "FileDescription" in obj.Data and obj.Data["FileDescription"] is not None:
                    version_info += f"FileDescription: {obj.Data['FileDescription']}\n"
                if "CompanyName" in obj.Data and obj.Data["CompanyName"] is not None:
                    version_info += f"CompanyName: {obj.Data['CompanyName']}\n"
                if "Version" in obj.Data and obj.Data["Version"] is not None:
                    version_info += f"FileVersion: {obj.Data['Version']}\n"

                if version_info != "":
                    file_info_pb.version_info = version_info

                msg = pb.FileInformationIngestionMessage()
                msg.metadata.CopyFrom(metadata)
                msg.data.append(file_info_pb)

                await self.create_task(self.service_output_q.Send(msg.SerializeToString()))
