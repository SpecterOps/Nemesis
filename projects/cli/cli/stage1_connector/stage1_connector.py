# main.py
import asyncio
import logging
import tempfile

import urllib3
from cli.config import Config, OutflankConfig
from cli.log import setup_logging
from cli.nemesis_client import NemesisClient, PreviewNemesisClient
from cli.preflight import check_nemesis_availability
from cli.stage1_connector.cache import ImplantCache
from cli.stage1_connector.download_monitor import OutflankDownloadMonitor
from cli.stage1_connector.download_processor import OutflankDownloadProcessor
from cli.stage1_connector.outflankc2_client import OutflankC2Client

setup_logging()


async def run_outflank_connector(config: Config, logger: logging.Logger, dry_run: bool = False):
    """Main connector logic"""

    if not config.validate_https_certs:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    tasks = []
    tempdir = None
    try:
        if not config.outflank:
            logger.warning("No C2 platforms configured")
            return

        original_cache = config.cache_db_path
        try:
            if dry_run:
                tempdir = tempfile.TemporaryDirectory(prefix="nemesis-outflank-dryrun-")
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
                for outflank_config in config.outflank:
                    tasks.append(
                        asyncio.create_task(setup_outflank_monitor(outflank_config, config, logger, nemesis_client))
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


async def setup_outflank_monitor(
    outflank_config: OutflankConfig, config: Config, logger: logging.Logger, nemesis_client: NemesisClient
):
    """Set up and run a single Outflank C2 manager instance"""
    base_url = str(outflank_config.url)
    username = outflank_config.credential.username
    password = outflank_config.credential.password

    logger.info(f"Connecting to Outflank C2 at {base_url}")
    if outflank_config.downloads_dir_path:
        logger.info(f"Using upload path: {outflank_config.downloads_dir_path}")

    async with OutflankC2Client(
        base_url=base_url,
        verify_ssl=config.validate_https_certs,
    ) as outflank_client:
        # Authenticate
        if not await outflank_client.authenticate(username, password):
            # logger.error(f"Authentication failed for {base_url}")
            raise Exception(f"Authentication failed for {base_url}")

        project = await outflank_client.get_project_info()
        if not project or not project["name"]:
            raise Exception(f"Failed to get project info for {base_url}: project={project}")

        # Initialize components
        implant_cache = ImplantCache(outflank_client)
        await implant_cache.initialize()

        # Initialize processor with the client
        if outflank_config.downloads_dir_path:
            # Grab files from stage1's download directory
            nemesis_file_processor = OutflankDownloadProcessor(
                config.cache_db_path,
                nemesis_client,
                project["name"],
                outflank_downloads_dir_path=outflank_config.downloads_dir_path,
            )
        else:
            # Grab stage1 download files from its API
            nemesis_file_processor = OutflankDownloadProcessor(
                config.cache_db_path,
                nemesis_client,
                project["name"],
                outflank=outflank_client,
            )

        monitor = OutflankDownloadMonitor(
            outflank_client,
            implant_cache,
            nemesis_file_processor,
            outflank_config.poll_interval_sec,
        )

        # Start the manager
        logger.info(f"Starting Outflank download monitor for {base_url}")
        try:
            await monitor.start()
        finally:
            nemesis_file_processor.close()


# async def setup_mythic_manager(mythic_config: MythicConfig, config: Config, logger: logging.Logger):
#     """Set up and run a single Mythic C2 manager instance"""
#     base_url = str(mythic_config.url)
#     logger.info(f"Connecting to Mythic C2 at {base_url}")

#     async with MythicC2Client(
#         base_url=base_url,
#         verify_ssl=config.validate_https_certs,
#     ) as mythic_client:
#         # Initialize components similar to Outflank
#         nemesis_client = NemesisClient(config.nemesis)

#         # Initialize processor with the client
#         nemesis_file_processor = MythicDownloadProcessor(
#             config.cache_db_path,
#             nemesis_client,
#             mythic=mythic_client,
#         )

#         manager = MythicDownloadMonitor(
#             mythic_client,
#             nemesis_file_processor,
#             mythic_config.poll_interval_sec,
#         )

#         # Start the manager
#         logger.info(f"Starting Mythic download manager for {base_url}")
#         await manager.start()
