"""Nemesis preflight checks for the Outflank connector."""

from unittest.mock import MagicMock, patch

import pytest
from cli.config import Config
from cli.stage1_connector.stage1_connector import run_outflank_connector
from common.models2.api import ErrorResponse, HealthResponse

MODULE = "cli.stage1_connector.stage1_connector"


@pytest.fixture
def config():
    return Config(
        nemesis={"url": "https://nemesis.local", "credential": {"username": "n", "password": "n"}},
        outflank=[{"url": "https://outflank.local", "credential": {"username": "connector", "password": "password"}}],
        conn_timeout_sec=5,
        validate_https_certs=True,
    )


@pytest.mark.asyncio
async def test_preflight_before_outflank(config):
    events = []

    def health(**kwargs):
        events.append("preflight")
        return HealthResponse(status="healthy")

    async def monitor(*args):
        events.append("monitor")

    with patch(f"{MODULE}.NemesisClient") as client, patch(f"{MODULE}.setup_outflank_monitor", side_effect=monitor):
        client.return_value.get_health.side_effect = health
        await run_outflank_connector(config, MagicMock())
        client.return_value.get_health.assert_called_once_with(timeout=5, verify_ssl=True)
    assert events == ["preflight", "monitor"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "health",
    [ErrorResponse(detail="Connection refused"), ErrorResponse(detail="HTTP 401"), HealthResponse(status="unhealthy")],
)
async def test_failed_preflight_prevents_outflank_startup(config, health):
    with patch(f"{MODULE}.NemesisClient") as client, patch(f"{MODULE}.setup_outflank_monitor") as setup:
        client.return_value.get_health.return_value = health
        with pytest.raises(RuntimeError, match="Nemesis preflight check failed"):
            await run_outflank_connector(config, MagicMock())
        setup.assert_not_called()


@pytest.mark.asyncio
async def test_monitor_errors_propagate(config):
    with (
        patch(f"{MODULE}.NemesisClient") as client,
        patch(f"{MODULE}.setup_outflank_monitor", side_effect=RuntimeError("Server disconnected")),
    ):
        client.return_value.get_health.return_value = HealthResponse(status="healthy")
        with pytest.raises(RuntimeError, match="Server disconnected"):
            await run_outflank_connector(config, MagicMock())


@pytest.mark.asyncio
async def test_no_servers_skips_preflight(config):
    config.outflank = []
    with patch(f"{MODULE}.NemesisClient") as client:
        await run_outflank_connector(config, MagicMock())
        client.assert_not_called()


@pytest.mark.parametrize("connector", ["connect-mythic", "connect-outflank"])
def test_failed_preflight_exits_nonzero(connector, tmp_path):
    from cli.main import cli
    from click.testing import CliRunner

    config_path = tmp_path / "connector.yaml"
    config_path.write_text("{}")
    with (
        patch("cli.main.load_config", return_value=MagicMock()),
        patch("cli.main.start", side_effect=RuntimeError("Nemesis preflight check failed")),
        patch("cli.main.run_outflank_connector", side_effect=RuntimeError("Nemesis preflight check failed")),
    ):
        result = CliRunner().invoke(cli, [connector, "--config", str(config_path)])
    assert result.exit_code == 1
