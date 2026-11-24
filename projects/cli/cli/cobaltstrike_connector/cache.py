import logging

from cli.cobaltstrike_connector.cobaltstrike_client import Beacon, CobaltStrikeClient


class ImplantCache:
    """Beacon lookup cache. A miss refreshes the full beacon list at most once per poll cycle."""

    def __init__(self, client: CobaltStrikeClient):
        self.client = client
        self.cache: dict[str, Beacon] = {}
        self.logger = logging.getLogger(__name__)
        self._refreshed_this_poll = False

    async def initialize(self):
        """Initialize the cache with current beacons"""
        try:
            beacons = await self.client.get_beacons()
            for beacon in beacons:
                self.cache[beacon.bid] = beacon
            self.logger.info(f"Initialized cache with {len(beacons)} beacons")
        except Exception as e:
            self.logger.error(f"Failed to initialize beacon cache: {e}")
            raise

    def start_poll(self) -> None:
        """Allow one more refresh on a cache miss; call once at the start of each poll cycle."""
        self._refreshed_this_poll = False

    async def get_beacon(self, bid: str) -> Beacon | None:
        """Get beacon from cache, refreshing the list (once per poll) if not found"""
        if bid in self.cache:
            return self.cache[bid]
        if self._refreshed_this_poll:
            return None
        self._refreshed_this_poll = True

        try:
            # Refresh entire cache as there's no endpoint for single beacon
            beacons = await self.client.get_beacons()
            for beacon in beacons:
                self.cache[beacon.bid] = beacon

            return self.cache.get(bid)
        except Exception as e:
            self.logger.error(f"Failed to fetch beacon {bid}: {e}")
            return None
