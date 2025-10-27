# Standard library imports
import logging

import click
import urllib3
from cli.mythic_connector.config import get_settings


async def start(config_path: str, debug: bool) -> None:
    cfg = get_settings(config_path)

    logging.basicConfig(format="%(levelname)s %(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    logger = logging.getLogger("mythic_connector")

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if cfg.networking.validate_https_certs is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        from cli.mythic_connector.sync import SyncService

        service = SyncService(cfg)
        await service.run()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        raise click.Abort() from e
