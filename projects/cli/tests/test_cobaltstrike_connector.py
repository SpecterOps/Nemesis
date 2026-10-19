"""Startup preflight and failure propagation for the Cobalt Strike connector."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cli.cobaltstrike_connector.cobaltstrike_connector import (
    run_cobaltstrike_connector,
    setup_cobaltstrike_monitor,
)
from cli.config import Config
from common.models2.api import ErrorResponse, HealthResponse

MODULE = "cli.cobaltstrike_connector.cobaltstrike_connector"


@pytest.fixture
def config():
    return Config(
        nemesis={"url": "https://nemesis.local", "credential": {"username": "n", "password": "n"}},
        cobaltstrike=[
            {
                "url": "https://cs.local:50443",
                "credential": {"username": "connector", "password": "password"},
                "project": "test",
            }
        ],
        conn_timeout_sec=5,
        validate_https_certs=False,
    )


@pytest.mark.asyncio
async def test_preflight_runs_before_cobalt_strike(config):
    events = []

    def health(**kwargs):
        events.append("preflight")
        return HealthResponse(status="healthy")

    async def monitor(*args):
        events.append("monitor")

    with (
        patch(f"{MODULE}.NemesisClient") as client,
        patch(f"{MODULE}.setup_cobaltstrike_monitor", side_effect=monitor) as setup,
    ):
        client.return_value.__aenter__.return_value = client.return_value
        client.return_value.get_health = AsyncMock(side_effect=health)
        await run_cobaltstrike_connector(config, MagicMock())
        client.return_value.get_health.assert_called_once_with(timeout=5)
        setup.assert_awaited_once()
        assert setup.await_args.args[3] is client.return_value
    assert events == ["preflight", "monitor"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "health, message",
    [
        (ErrorResponse(detail="Connection refused"), "Connection refused"),
        (ErrorResponse(detail="HTTP 401"), "HTTP 401"),
        (HealthResponse(status="unhealthy"), "unhealthy"),
    ],
)
async def test_failed_preflight_prevents_cobalt_strike_startup(config, health, message):
    logger = MagicMock()
    with patch(f"{MODULE}.NemesisClient") as client, patch(f"{MODULE}.setup_cobaltstrike_monitor") as setup:
        client.return_value.__aenter__.return_value = client.return_value
        client.return_value.get_health = AsyncMock(return_value=health)
        with pytest.raises(RuntimeError, match=f"Nemesis preflight check failed.*{message}"):
            await run_cobaltstrike_connector(config, logger)
        setup.assert_not_called()
    logger.info.assert_called_with("Shutting down")


@pytest.mark.asyncio
async def test_failure_cancels_other_monitors(config):
    config.cobaltstrike.append(config.cobaltstrike[0].model_copy(update={"url": "https://cs2.local"}))
    started = asyncio.Event()
    cancelled = asyncio.Event()
    lifecycle = []

    async def monitor(cs_config, *_args):
        if str(cs_config.url) == "https://cs2.local":
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
                lifecycle.append("monitor_cancelled")
        else:
            await started.wait()
            raise RuntimeError("Server disconnected")

    with patch(f"{MODULE}.NemesisClient") as client, patch(f"{MODULE}.setup_cobaltstrike_monitor", side_effect=monitor):
        client.return_value.__aenter__.return_value = client.return_value
        client.return_value.get_health = AsyncMock(return_value=HealthResponse(status="healthy"))

        async def close_client(*_args):
            lifecycle.append("client_closed")

        client.return_value.__aexit__ = AsyncMock(side_effect=close_client)
        with pytest.raises(RuntimeError, match="Server disconnected"):
            await asyncio.wait_for(run_cobaltstrike_connector(config, MagicMock()), timeout=2)
    assert cancelled.is_set()
    assert lifecycle == ["monitor_cancelled", "client_closed"]


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [None, RuntimeError("Server disconnected")])
async def test_authentication_failure_includes_server(config, error):
    with patch(f"{MODULE}.CobaltStrikeClient") as client, patch(f"{MODULE}.ImplantCache") as cache:
        session = client.return_value.__aenter__.return_value
        session.authenticate = AsyncMock(return_value=False, side_effect=error)
        with pytest.raises(RuntimeError, match="Cobalt Strike authentication failed for https://cs.local:50443"):
            await setup_cobaltstrike_monitor(config.cobaltstrike[0], config, MagicMock(), MagicMock())
        cache.assert_not_called()
        client.return_value.__aexit__.assert_awaited_once()


@pytest.mark.asyncio
async def test_no_servers_skips_preflight(config):
    config.cobaltstrike = []
    with patch(f"{MODULE}.NemesisClient") as client:
        await run_cobaltstrike_connector(config, MagicMock())
        client.assert_not_called()


def test_cli_failure_exits_nonzero(tmp_path):
    from cli.main import cli
    from click.testing import CliRunner

    config_path = tmp_path / "connector.yaml"
    config_path.write_text("{}")
    with (
        patch("cli.main.load_config", return_value=MagicMock()),
        patch("cli.main.setup_logging") as logging,
        patch("cli.main.run_cobaltstrike_connector", side_effect=RuntimeError("Nemesis preflight check failed")),
    ):
        result = CliRunner().invoke(cli, ["connect-cobaltstrike", "--config", str(config_path)])
    assert result.exit_code == 1
    assert "Nemesis preflight check failed" in str(logging.return_value.exception.call_args.args[1])
