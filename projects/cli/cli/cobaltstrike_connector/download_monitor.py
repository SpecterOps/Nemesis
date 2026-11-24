import asyncio
import logging
from asyncio import Queue

from cli.cobaltstrike_connector.cache import ImplantCache
from cli.cobaltstrike_connector.cobaltstrike_client import CobaltStrikeClient
from cli.cobaltstrike_connector.download_processor import CobaltStrikeDownloadProcessor

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
        # Downloads queued or being processed; never queued twice.
        self.in_flight: set[str] = set()
        # Downloads already warned about for a missing beacon, so the warning is logged once.
        self._missing_beacon_warned: set[str] = set()

    async def process_queue(self):
        """Process downloads from the queue"""
        while self.is_running:
            download, beacon = await self.queue.get()
            try:
                # Another path may have finished it since it was queued.
                if not self.nemesis_file_processor.is_processed(download):
                    await self.nemesis_file_processor.process_cobaltstrike_download(download, beacon)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Error processing download from queue: {e}")
            finally:
                self.in_flight.discard(download.id)
                self.queue.task_done()

    async def poll_once(self) -> None:
        """Queue every download that is not finished, not in flight, and not waiting out a retry delay."""
        downloads = await self.cobalt_strike_client.get_downloads()
        logger.debug(f"Found {len(downloads)} Cobalt Strike downloads")
        self.beacon_cache.start_poll()

        for download in downloads:
            if download.id in self.in_flight:
                continue
            if not self.nemesis_file_processor.is_due(download):
                logger.debug(f"Download {download.id} is finished or waiting to retry")
                continue

            beacon = await self.beacon_cache.get_beacon(download.bid)
            if beacon is None and download.id not in self._missing_beacon_warned:
                self._missing_beacon_warned.add(download.id)
                logger.warning(f"Could not find beacon {download.bid} for download {download.id}; uploading without it")

            self.in_flight.add(download.id)
            await self.queue.put((download, beacon))
            logger.info(f"Queued download for processing. ID: {download.id}. Path: {download.path}")

    async def get_downloads(self):
        """Check for new downloads and add them to queue"""
        while self.is_running:
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
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
