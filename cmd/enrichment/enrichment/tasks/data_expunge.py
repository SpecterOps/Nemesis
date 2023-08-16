# Standard Libraries
import asyncio
from datetime import datetime, timezone

# 3rd Party Libraries
import structlog
from elasticsearch import AsyncElasticsearch
from enrichment.lib.nemesis_db import NemesisDb
from nemesiscommon.constants import ALL_ES_INDICIES
from nemesiscommon.tasking import TaskInterface

logger = structlog.get_logger(module=__name__)


class DataExpunge(TaskInterface):
    """
    Class responsible for expunging data from PostgreSQL and Elasticsearch
    that's past its expiration date.
    """
    es_client: AsyncElasticsearch
    db: NemesisDb

    def __init__(
        self,
        es_client: AsyncElasticsearch,
        db: NemesisDb,
    ):
        self.db = db
        self.es_client = es_client

    async def run(self) -> None:
        await logger.ainfo("Starting the Data Expunge service")

        while True:
            try:
                # get the current day in UTC
                utc_current_day = f"{datetime.now(timezone.utc).date()}"

                await logger.ainfo("Expunging expired data from Elasticsearch indexes")

                for ES_INDEX in ALL_ES_INDICIES:
                    if await self.es_client.indices.exists(index=ES_INDEX):
                        # delete_by_query for any documents with an expiration that's passed
                        query = {"range": {"metadata.expiration": {"lte": utc_current_day}}}
                        await self.es_client.delete_by_query(index=ES_INDEX, query=query)

                await logger.ainfo("Expired data expunged from Elasticsearch indexes")

                await logger.ainfo("Expunging expired data from PostgreSQL tables")
                await self.db.expunge_expirated_data()
                await logger.ainfo("Expired data expunged from PostgreSQL tables")
            except Exception as e:
                await logger.aerror(f"Exception running data expungement: {e}")

            # run every 6 hours
            await asyncio.sleep(60 * 60 * 6)
