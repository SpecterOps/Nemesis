"""The connector commands' --help output tells operators where processing state lives."""

from pathlib import Path

import pytest
from cli.main import cli
from click.testing import CliRunner


@pytest.mark.parametrize("command", ["connect-outflank", "connect-cobaltstrike"])
def test_help_shows_xdg_state_dir(command, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    result = CliRunner().invoke(cli, [command, "--help"], terminal_width=500)
    assert result.exit_code == 0
    assert "cache_db_path" in result.output
    assert str(tmp_path / "xdg" / "nemesis" / "connectors") in result.output


@pytest.mark.parametrize("command", ["connect-outflank", "connect-cobaltstrike"])
def test_help_falls_back_to_home_state_dir(command, monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    result = CliRunner().invoke(cli, [command, "--help"], terminal_width=500)
    assert result.exit_code == 0
    assert str(tmp_path / ".local" / "state" / "nemesis" / "connectors") in result.output


def test_mythic_help_shows_db_path(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    result = CliRunner().invoke(cli, ["connect-mythic", "--help"], terminal_width=500)
    assert result.exit_code == 0
    assert "db.path" in result.output
    assert str(Path(tmp_path) / "xdg" / "nemesis" / "connectors") in result.output
    assert "cache_db_path" not in result.output


@pytest.mark.parametrize("command", ["submit", "monitor"])
def test_password_is_required_without_a_public_default(command, tmp_path, monkeypatch):
    monkeypatch.delenv("NEMESIS_PASSWORD", raising=False)
    result = CliRunner().invoke(cli, [command, str(tmp_path)])
    assert result.exit_code == 2
    assert "--password" in result.output and "NEMESIS_PASSWORD" in result.output
