from dataclasses import dataclass, asdict
import logging
import os
from typing import List, Optional, AsyncGenerator
import aiohttp
from datetime import datetime, timedelta
import asyncio

from sliver_service.pb.commonpb import common_pb2 as commonpb
from sliver_service.pb.clientpb import client_pb2 as clientpb

from sliver_service.sliver import SliverClientConfig, SliverClient

logger = logging.getLogger(__name__)


class Config:
    def __init__(self):
        self.expiration_days = 30
        self.nemesis_http_server = self.get_env_var("NEMESIS_HTTP_SERVER")
        self.nemesis_creds = self.get_env_var("NEMESIS_CREDS")
        self.elasticsearch_user = self.get_env_var("ELASTICSEARCH_USER")
        self.elasticsearch_password = self.get_env_var("ELASTICSEARCH_PASSWORD")

        self.sliver_operator = self.get_env_var("SLIVER_OPERATOR")
        self.sliver_lhost = self.get_env_var("SLIVER_LHOST")
        self.sliver_lport = int(self.get_env_var("SLIVER_LPORT"))
        self.sliver_ca_cert = self.get_env_var("SLIVER_CA_CERT")
        self.sliver_cert = self.get_env_var("SLIVER_CERT")
        self.sliver_private_key = self.get_env_var("SLIVER_PRIVATE_KEY")
        self.sliver_token = self.get_env_var("SLIVER_TOKEN")
        self.nemesis_url = f"{self.nemesis_http_server}/api"
        self.elasticsearch_url = f"{self.nemesis_http_server}/elastic"
        self.kibana_url = f"{self.nemesis_http_server}/kibana"

    @staticmethod
    def get_env_var(name):
        value = os.environ.get(name)
        if value is None:
            raise ValueError(f"{name} environment variable is not set.")
        return value.replace("\\n", "\n") if isinstance(value, str) else value


@dataclass
class Metadata:
    agent_id: str
    agent_type: str
    automated: bool
    data_type: str
    expiration: str
    source: str
    project: str
    timestamp: str


async def nemesis_post_data(
    session: aiohttp.ClientSession,
    config: Config,
    metadata: Metadata,
    content: List[dict],
) -> Optional[dict]:
    data = {"metadata": asdict(metadata), "data": content}
    url = f"{config.nemesis_url}/data"
    async with session.post(
        url, json=data, auth=aiohttp.BasicAuth(*config.nemesis_creds.split(":"))
    ) as resp:
        if resp.status != 200:
            logger.error(
                f"Error posting to Nemesis URL {url}. Status: {resp.status}. Message: {await resp.text()}"
            )
            return None
        return await resp.json()


async def nemesis_post_file(
    session: aiohttp.ClientSession, config: Config, file_bytes: bytes
) -> Optional[str]:
    url = f"{config.nemesis_url}/file"
    async with session.post(
        url,
        data=file_bytes,
        auth=aiohttp.BasicAuth(*config.nemesis_creds.split(":")),
        headers={"Content-Type": "application/octet-stream"},
    ) as resp:
        if resp.status != 200:
            logger.error(
                f"Error uploading file to Nemesis URL {url}. Status: {resp.status}"
            )
            return None
        json_result = await resp.json()
        return json_result.get("object_id")


def generate_config() -> SliverClientConfig:
    config = Config()
    return SliverClientConfig(
        config.sliver_operator,
        config.sliver_lhost,
        config.sliver_lport,
        config.sliver_ca_cert,
        config.sliver_cert,
        config.sliver_private_key,
        config.sliver_token,
    )


@dataclass
class FileData:
    path: str
    size: int
    object_id: str


async def get_loot_from_id(
    client: SliverClient, loot_id: str
) -> Optional[clientpb.Loot]:
    loots = (await client.loot_all()).Loot
    for loot in loots:
        if loot.ID == loot_id:
            content = await client.loot_content(loot)
            return content
    return None


async def on_loot_added(client: SliverClient) -> AsyncGenerator[str, clientpb.Loot]:
    async for event in client.events():
        if event.EventType == "loot-added":
            loot_id = event.Data.decode()
            yield loot_id, await get_loot_from_id(client, loot_id)


async def on_loot_file(
    session: aiohttp.ClientSession, config: Config, loot: clientpb.Loot
) -> None:
    timestamp = datetime.now()
    nemesis_file_id = await nemesis_post_file(session, config, loot.File.Data)
    logger.info(f"File posted to nemesis. nemesis_file_id: {nemesis_file_id}")
    metadata = Metadata(
        agent_id="",
        agent_type="sliver",
        automated=True,
        data_type="file_data",
        expiration=(timestamp + timedelta(days=config.expiration_days)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        ),
        source="",
        project="",
        timestamp=timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    )
    file_data = [FileData(path=loot.File.Name, size=0, object_id=nemesis_file_id)]
    await nemesis_post_data(session, config, metadata, file_data)


async def main() -> None:
    config = generate_config()

    client = SliverClient(config)
    logger.info("Connected to server ...")
    await client.connect()

    logger.info("Listening for events")
    async with aiohttp.ClientSession() as session:
        config = Config()
        async for loot_id, loot in on_loot_added(client):
            if loot is None:
                logger.error(f"Loot {loot_id} not found")
                continue
            logger.info("NEW FILE ADDED!")
            await on_loot_file(session, config, loot)


if __name__ == "__main__":
    logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)
    asyncio.run(main())
