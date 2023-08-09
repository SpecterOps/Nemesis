# Standard Libraries
from abc import abstractmethod
from enum import StrEnum
from typing import Optional

# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
import structlog
from google.protobuf.json_format import MessageToDict
from nemesiscommon.messaging_rabbitmq import NemesisRabbitMQProducer

logger = structlog.get_logger(module=__name__)


class AlertType(StrEnum):
    SLACK = "slack"


class AlerterInterface:
    @abstractmethod
    async def alert(self, text: str) -> None:
        pass

    @abstractmethod
    async def file_data_alert(self, file_data: pb.FileDataEnriched, metadata: pb.Metadata, title: Optional[str] = "", text: Optional[str] = ""):
        pass


class NemesisAlerter(AlerterInterface):
    alert_queue: NemesisRabbitMQProducer
    kibana_url: str

    def __init__(self, alert_queue: NemesisRabbitMQProducer, kibana_url: str):
        self.alert_queue = alert_queue
        self.kibana_url = kibana_url

    async def alert(self, text: str) -> None:
        alert_msg = pb.Alert()
        alert_msg.type = AlertType.SLACK.value
        alert_msg.text = text

        await self.alert_queue.Send(alert_msg.SerializeToString())

    async def file_data_alert(self, file_data: pb.FileDataEnriched, metadata: pb.Metadata, title: Optional[str] = "", text: Optional[str] = ""):
        file_name = self.sanitize_file_path(file_data.name)
        sha1_hash = file_data.hashes.sha1

        header = f"*{title}*\n" if title else ""
        text = f"\n{text}" if text else ""

        full_kibana_url = f"{self.kibana_url}app/discover#/?_a=(filters:!((query:(match_phrase:(objectId:'{file_data.object_id}')))),index:'26360ae8-a518-4dac-b499-ef682d3f6bac')&_g=(time:(from:now-1y%2Fd,to:now))"
        kibana_footer = f"\n<{full_kibana_url}|*File in Kibana*>"

        try:
            metadata_dict = MessageToDict(metadata, preserving_proto_field_name=True)
            timestamp = metadata_dict["timestamp"]
            agent_type = metadata_dict["agent_type"]
            agent_id = metadata_dict["agent_id"]
            message = f"{header}*File:* {file_name}\n*SHA1:* {sha1_hash}\n*Downloaded:* {timestamp}\n*Agent:* {agent_id} (type: {agent_type}){text}{kibana_footer}"

            await self.alert(text=message)

        except Exception as e:
            await logger.aexception(
                e,
                "Error constructing message from metadata in send_file_alert"
            )

    def sanitize_file_path(self, file_path: str, num_chars=4):
        """Replaces all but the first `num_chars` characters of a file path string with *'s"""
        return file_path[0:num_chars] + len(file_path[num_chars:]) * "*" if file_path else file_path
