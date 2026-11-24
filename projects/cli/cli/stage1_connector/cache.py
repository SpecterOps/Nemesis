import logging

from cli.stage1_connector.outflankc2_client import Implant, OutflankC2Client


class ImplantCache:
    """Implant lookup cache. A miss refreshes the full implant list at most once per poll cycle."""

    def __init__(self, client: OutflankC2Client):
        self.client = client
        self.cache: dict[str, Implant] = {}
        self.logger = logging.getLogger(__name__)
        self._refreshed_this_poll = False

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

    def start_poll(self) -> None:
        """Allow one more refresh on a cache miss; call once at the start of each poll cycle."""
        self._refreshed_this_poll = False

    async def get_implant(self, uid: str) -> Implant | None:
        """Get implant from cache, refreshing the list (once per poll) if not found"""
        if uid in self.cache:
            return self.cache[uid]
        if self._refreshed_this_poll:
            return None
        self._refreshed_this_poll = True

        try:
            # Refresh entire cache as there's no endpoint for single implant
            implants = await self.client.get_implants()
            for implant in implants:
                self.cache[implant.uid] = implant

            return self.cache.get(uid)
        except Exception as e:
            self.logger.error(f"Failed to fetch implant {uid}: {e}")
            return None
