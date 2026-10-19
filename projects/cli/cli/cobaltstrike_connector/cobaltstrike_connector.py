# main.py
import asyncio
import logging
import tempfile

import urllib3
from cli.cobaltstrike_connector.cache import ImplantCache
from cli.cobaltstrike_connector.cobaltstrike_client import CobaltStrikeClient
from cli.cobaltstrike_connector.download_monitor import CobaltStrikeDownloadMonitor
from cli.cobaltstrike_connector.download_processor import CobaltStrikeDownloadProcessor
from cli.config import CobaltStrikeConfig, Config
from cli.log import setup_logging
from cli.nemesis_client import NemesisClient, PreviewNemesisClient
from cli.preflight import check_nemesis_availability

setup_logging()


async def run_cobaltstrike_connector(config: Config, logger: logging.Logger, dry_run: bool = False):
    """Main connector logic"""

    if not config.validate_https_certs:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    tasks = []
    tempdir = None
    try:
        if not config.cobaltstrike:
            logger.warning("No C2 platforms configured")
            return

        original_cache = config.cache_db_path
        try:
            if dry_run:
                tempdir = tempfile.TemporaryDirectory(prefix="nemesis-cobaltstrike-dryrun-")
                config.cache_db_path = tempdir.name + "/state.db"
            client = (
                PreviewNemesisClient()
                if dry_run
                else NemesisClient(
                    config.nemesis, verify_ssl=config.validate_https_certs, connect_timeout=config.conn_timeout_sec
                )
            )
            async with client as nemesis_client:
                if not dry_run:
                    await check_nemesis_availability(nemesis_client, timeout=config.conn_timeout_sec, logger=logger)
                for cobaltstrike_config in config.cobaltstrike:
                    tasks.append(
                        asyncio.create_task(
                            setup_cobaltstrike_monitor(cobaltstrike_config, config, logger, nemesis_client)
                        )
                    )
                try:
                    await asyncio.gather(*tasks)
                finally:
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            config.cache_db_path = original_cache
            if tempdir is not None:
                tempdir.cleanup()

    except Exception as e:
        logger.error(f"Error running connector: {e}")
        raise
    finally:
        logger.info("Shutting down")


async def setup_cobaltstrike_monitor(
    cobaltstrike_config: CobaltStrikeConfig, config: Config, logger: logging.Logger, nemesis_client: NemesisClient
):
    """Set up and run a single Cobalt Strike manager instance"""
    base_url = str(cobaltstrike_config.url)
    username = cobaltstrike_config.credential.username
    password = cobaltstrike_config.credential.password
    logger.info(f"Connecting to Cobalt Strike at {base_url}")
    async with CobaltStrikeClient(
        base_url=base_url,
        verify_ssl=config.validate_https_certs,
    ) as cobaltstrike_client:
        # Authenticate
        try:
            authenticated = await cobaltstrike_client.authenticate(username, password)
        except Exception as e:
            raise RuntimeError(f"Cobalt Strike authentication failed for {base_url}: {e}") from e
        if not authenticated:
            raise RuntimeError(
                f"Cobalt Strike authentication failed for {base_url}: credentials rejected or token missing"
            )

        # Initialize components
        implant_cache = ImplantCache(cobaltstrike_client)
        await implant_cache.initialize()

        # Initialize processor with the client
        nemesis_file_processor = CobaltStrikeDownloadProcessor(
            config.cache_db_path,
            nemesis_client,
            cobaltstrike_config.project,
            cobalt_strike=cobaltstrike_client,
        )

        monitor = CobaltStrikeDownloadMonitor(
            cobaltstrike_client,
            implant_cache,
            nemesis_file_processor,
            cobaltstrike_config.poll_interval_sec,
        )

        # Start the manager
        logger.info(f"Starting Cobalt Strike download monitor for {base_url}")
        try:
            await monitor.start()
        except Exception as e:
            logger.error("Cobalt Strike monitor failed for %s: %s", base_url, e)
            raise
        finally:
            nemesis_file_processor.close()
