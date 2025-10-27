import logging

from cli.stage1_connector.outflankc2_client import Implant, OutflankC2Client


class ImplantCache:
    def __init__(self, client: OutflankC2Client):
        self.client = client
        self.cache: dict[str, Implant] = {}
        self.logger = logging.getLogger(__name__)

    async def initialize(self):
        """Initialize the cache with current implants"""
        try:
            implants = await self.client.get_implants()
            for implant in implants:
                self.cache[implant.uid] = implant
            self.logger.info(f"Initialized cache with {len(implants)} implants")
        except Exception as e:
            self.logger.error(f"Failed to initialize implant cache: {e}")
            raise

    async def get_implant(self, uid: str) -> Implant | None:
        """Get implant from cache, fetching from API if not found"""
        if uid in self.cache:
            return self.cache[uid]

        try:
            # Refresh entire cache as there's no endpoint for single implant
            implants = await self.client.get_implants()
            for implant in implants:
                self.cache[implant.uid] = implant

            return self.cache.get(uid)
        except Exception as e:
            self.logger.error(f"Failed to fetch implant {uid}: {e}")
            return None
