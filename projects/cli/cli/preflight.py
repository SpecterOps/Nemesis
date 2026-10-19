"""Shared startup checks for C2 connectors."""

import asyncio
import logging

from cli.nemesis_client import NemesisClient
from common.models2.api import ErrorResponse


async def check_nemesis_availability(
    client: NemesisClient, *, timeout: float, verify_ssl: bool, logger: logging.Logger
) -> None:
    """Require a healthy Nemesis API before starting a connector."""
    logger.info("Checking Nemesis availability at %s", client.cfg.url)
    health = await asyncio.to_thread(client.get_health, timeout=timeout, verify_ssl=verify_ssl)
    if isinstance(health, ErrorResponse):
        raise RuntimeError(f"Nemesis preflight check failed for {client.cfg.url}: {health.detail}")
    if health.status != "healthy":
        raise RuntimeError(f"Nemesis preflight check failed for {client.cfg.url}: service status is {health.status!r}")
    logger.info("Nemesis preflight check passed")
