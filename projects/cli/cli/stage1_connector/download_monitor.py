import asyncio
import logging
from asyncio import Queue

from cli.stage1_connector.cache import ImplantCache
from cli.stage1_connector.download_processor import OutflankDownloadProcessor
from cli.stage1_connector.outflankc2_client import OutflankC2Client

logger = logging.getLogger(__name__)


class OutflankDownloadMonitor:
    """Monitors and processes Outflank C2 downloads.

    This class continuously polls for new downloads from an Outflank C2 server,
    verifies if they've been previously processed, and submits unprocessed downloads
    to a processing queue. It maintains a background worker that processes queued
    downloads using the Nemesis file processor.

    Attributes:
        outflank_client (OutflankC2Client): Client for interacting with Outflank C2 server
        implant_cache (ImplantCache): Cache for looking up implant information
        nemesis_file_processor (NemesisFileProcessor): Processor for handling downloaded files
        polling_interval (int): Seconds to wait between polling for new downloads
        queue (Queue): Async queue for managing download processing
        is_running (bool): Flag indicating if the processor is currently running

    Example:
        processor = OutflankDownloadProcessor(client, cache, file_processor)
        await processor.start()  # Begins monitoring and processing downloads
        await processor.stop()   # Gracefully stops processing
    """

    def __init__(
        self,
        outflank_client: OutflankC2Client,
        implant_cache: ImplantCache,
        nemesis_file_processor: OutflankDownloadProcessor,
        polling_interval: int = 60,
    ):
        self.outflank_client = outflank_client
        self.implant_cache = implant_cache
        self.nemesis_file_processor = nemesis_file_processor
        self.polling_interval = polling_interval
        self.queue: Queue = Queue()
        self.is_running = False
        # Downloads queued or being processed; never queued twice.
        self.in_flight: set[str] = set()
        # Downloads already warned about for a missing implant, so the warning is logged once.
        self._missing_implant_warned: set[str] = set()

    async def process_queue(self):
        """Process downloads from the queue"""
        while self.is_running:
            download, implant = await self.queue.get()
            try:
                # Another path may have finished it since it was queued.
                if not self.nemesis_file_processor.is_processed(download):
                    await self.nemesis_file_processor.process_outflank_download(download, implant)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Error processing download from queue: {e}")
            finally:
                self.in_flight.discard(download.uid)
                self.queue.task_done()

    async def poll_once(self) -> None:
        """Queue every download that is not finished, not in flight, and not waiting out a retry delay."""
        downloads = await self.outflank_client.get_downloads()
        logger.debug(f"Found {len(downloads)} Outflank downloads")
        self.implant_cache.start_poll()

        for download in downloads:
            if download.uid in self.in_flight:
                continue
            if not self.nemesis_file_processor.is_due(download):
                logger.debug(f"Download {download.uid} is finished or waiting to retry")
                continue
            if not download.is_complete:
                # Still transferring from the implant; pick it up on a later poll.
                logger.debug(f"Download {download.uid} is still in progress ({download.progress}); waiting")
                continue

            implant = await self.implant_cache.get_implant(download.implant_uid)
            if implant is None and download.uid not in self._missing_implant_warned:
                self._missing_implant_warned.add(download.uid)
                logger.warning(
                    f"Could not find implant {download.implant_uid} for download {download.uid}; uploading without it"
                )

            self.in_flight.add(download.uid)
            await self.queue.put((download, implant))
            logger.info(f"Queued download for processing. ID: {download.uid}. Path: {download.path}")

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
