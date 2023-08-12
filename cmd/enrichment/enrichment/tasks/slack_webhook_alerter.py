# Standard Libraries
import asyncio

# 3rd Party Libraries
import httpx
import nemesispb.nemesis_pb2 as pb
from nemesiscommon.messaging import MessageQueueConsumerInterface
from nemesiscommon.tasking import TaskInterface
from prometheus_async.aio import time as metrics
from prometheus_client import Summary


class SlackWebHookAlerter(TaskInterface):
    in_q_alert: MessageQueueConsumerInterface
    web_hook_url: str
    username: str
    emoji: str
    channel: str
    http_client: httpx.AsyncClient
    disable_alerting: bool

    def __init__(
        self,
        in_q_alert: MessageQueueConsumerInterface,
        web_hook_url: str,
        username: str,
        emoji: str,
        channel: str,
        http_client: httpx.AsyncClient,
        disable_alerting: bool = True,
    ) -> None:
        self.in_q_alert = in_q_alert
        self.web_hook_url = web_hook_url

        if not disable_alerting:
            if not channel.startswith("#"):
                channel = f"#{channel}"

            self.username = username
            self.emoji = emoji
            self.channel = channel
            self.http_client = http_client
            self.disable_alerting = disable_alerting

    async def run(self) -> None:
        await self.in_q_alert.Read(self.process_message)  # type: ignore
        await asyncio.Future()

    @metrics(Summary("process_alert", "Time spent processing an alert topic."))  # type: ignore
    async def process_message(self, event: pb.Alert) -> None:
        if not self.disable_alerting:
            await self.send_slack_message(event.text)

    async def send_slack_message(self, text: str) -> None:
        """Sends the supplied Slack message to the SLACK_ALERT_CHANNEL via SLACK_WEB_HOOK."""

        payload = {"username": self.username, "icon_emoji": self.emoji, "channel": self.channel, "text": text}
        r = await self.http_client.post(self.web_hook_url, json=payload)
        r.raise_for_status()
