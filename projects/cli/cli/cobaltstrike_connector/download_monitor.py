import asyncio
import logging
from asyncio import Queue

from cli.cobaltstrike_connector.cache import ImplantCache
from cli.cobaltstrike_connector.download_processor import CobaltStrikeDownloadProcessor
from cli.cobaltstrike_connector.cobaltstrike_client import CobaltStrikeClient

logger = logging.getLogger(__name__)


class CobaltStrikeDownloadMonitor:
    """Monitors and processes Cobalt Strike C2 downloads.

    This class continuously polls for new downloads from a Cobalt Strike C2 server,
    verifies if they've been previously processed, and submits unprocessed downloads
    to a processing queue. It maintains a background worker that processes queued
    downloads using the Nemesis file processor.

    Attributes:
        cobalt_strike_client (CobaltStrikeClient): Client for interacting with Cobalt Strike C2 server
        beacon_cache (ImplantCache): Cache for looking up beacon information
        nemesis_file_processor (NemesisFileProcessor): Processor for handling downloaded files
        polling_interval (int): Seconds to wait between polling for new downloads
        queue (Queue): Async queue for managing download processing
        is_running (bool): Flag indicating if the processor is currently running

    Example:
        processor = CobaltStrikeDownloadProcessor(client, cache, file_processor)
        await processor.start()  # Begins monitoring and processing downloads
        await processor.stop()   # Gracefully stops processing
    """

    def __init__(
        self,
        cobalt_strike_client: CobaltStrikeClient,
        beacon_cache: ImplantCache,
        nemesis_file_processor: CobaltStrikeDownloadProcessor,
        polling_interval: int = 60,
    ):
        self.cobalt_strike_client = cobalt_strike_client
        self.beacon_cache = beacon_cache
        self.nemesis_file_processor = nemesis_file_processor
        self.polling_interval = polling_interval
        self.queue: Queue = Queue()
        self.is_running = False

    async def process_queue(self):
        """Process downloads from the queue"""
        while self.is_running:
            try:
                download, beacon = await self.queue.get()
                await self.nemesis_file_processor.process_cobaltstrike_download(download, beacon)
                self.queue.task_done()
            except Exception as e:
                logger.error(f"Error processing download from queue: {e}")

    async def get_downloads(self):
        """Check for new downloads and add them to queue"""
        while self.is_running:
            try:
                downloads = await self.cobalt_strike_client.get_downloads()
                logger.debug(f"Found {len(downloads)} CobaltStrike downloads")

                for download in downloads:
                    if self.nemesis_file_processor.is_processed(download):
                        logger.debug(f"Download {download.id} has already been processed")
                        continue

                    beacon = await self.beacon_cache.get_beacon(download.bid)
                    if beacon:
                        await self.queue.put((download, beacon))
                        logger.info(f"Queued download for processing. ID: {download.id}. Path: {download.path}")
                    else:
                        logger.warning(f"Could not find beacon {download.bid} for download {download.id}")

            except Exception as e:
                logger.error(f"Error checking downloads: {e}")

            await asyncio.sleep(self.polling_interval)

    async def start(self):
        """Start the download manager"""
        self.is_running = True
        await asyncio.gather(
            self.process_queue(),
            self.get_downloads(),
        )

    async def stop(self):
        """Stop the download manager"""
        self.is_running = False
        # Wait for queue to be processed
        await self.queue.join()
        self.nemesis_file_processor.close()
