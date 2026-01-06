import logging

from cli.cobaltstrike_connector.cobaltstrike_client import Beacon, CobaltStrikeClient


class ImplantCache:
    def __init__(self, client: CobaltStrikeClient):
        self.client = client
        self.cache: dict[str, Beacon] = {}
        self.logger = logging.getLogger(__name__)

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

    async def get_beacon(self, bid: str) -> Beacon | None:
        """Get beacon from cache, fetching from API if not found"""
        if bid in self.cache:
            return self.cache[bid]

        try:
            # Refresh entire cache as there's no endpoint for single beacon
            beacons = await self.client.get_beacons()
            for beacon in beacons:
                self.cache[beacon.bid] = beacon

            return self.cache.get(bid)
        except Exception as e:
            self.logger.error(f"Failed to fetch beacon {bid}: {e}")
            return None
