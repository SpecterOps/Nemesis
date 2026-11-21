# Standard library imports
import logging
from dataclasses import replace

import click
import urllib3
from cli.mythic_connector.config import get_settings


async def start(config_path: str, debug: bool, dry_run: bool = False, ignore_cert_errors: bool = False) -> None:
    cfg = get_settings(config_path)
    if ignore_cert_errors:
        # get_settings() is cached, so build a modified copy rather than mutating the shared instance
        cfg = replace(cfg, networking=replace(cfg.networking, validate_https_certs=False))

    logging.basicConfig(format="%(levelname)s %(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    logger = logging.getLogger("mythic_connector")

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if cfg.networking.validate_https_certs is False:
        logger.warning("HTTPS certificate verification is disabled; connections can be intercepted")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        from cli.mythic_connector.sync import SyncService

        service = SyncService(cfg)
        await service.run(dry_run=dry_run)
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        raise click.Abort() from e
