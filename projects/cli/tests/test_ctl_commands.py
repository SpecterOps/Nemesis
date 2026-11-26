"""nemesis.toml loading and the start/stop/clean/status/logs/config commands (docker is faked)."""

from pathlib import Path

import pytest
from cli.ctl import compose
from cli.ctl.compose import Controller, Deployment, compose_command
from cli.ctl.config import ConfigError, load_config, load_effective_config
from cli.main import cli
from click.testing import CliRunner


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    root = tmp_path / "nemesis"
    (root / "tools").mkdir(parents=True)
    (root / "compose.base.yaml").write_text("")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("NEMESIS_CONFIG", raising=False)
    monkeypatch.delenv("NEMESIS_PROJECT_DIR", raising=False)
    monkeypatch.delenv("PHOENIX_ENABLED", raising=False)
    return root


@pytest.fixture
def calls(monkeypatch):
    """Record docker calls instead of running them."""
    recorded: list[tuple[list[str], dict[str, str]]] = []

    def fake_runner(argv, env, cwd, quiet):
        if argv[0].endswith("generate-version.sh"):
            Path(argv[1]).write_text("{}")
        if not quiet:
            recorded.append((list(argv), dict(env)))
        return 1 if quiet else 0  # `docker volume inspect` -> no existing data

    original_init = Controller.__init__

    def init(self, *args, **kwargs):
        kwargs["runner"] = fake_runner
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(Controller, "__init__", init)
    return recorded


def invoke(*args):
    return CliRunner().invoke(cli, list(args))


def write_toml(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


# --- config file ---


def test_load_config_values(tmp_path):
    cfg = load_config(
        write_toml(
            tmp_path / "n.toml",
            '[deploy]\nenvironment = "dev"\nprofiles = ["llm"]\nbuild = true\n'
            'phoenix_enabled = false\nproject_dir = "sub"\n',
        )
    )
    assert (cfg.environment, cfg.profiles, cfg.build, cfg.phoenix_enabled) == ("dev", ["llm"], True, False)
    assert cfg.project_dir == (tmp_path / "sub").resolve()


def test_empty_config_is_all_defaults(tmp_path):
    cfg = load_config(write_toml(tmp_path / "n.toml", ""))
    assert cfg.environment is None and cfg.profiles == [] and cfg.build is None


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ('[deploy]\nenvironment = "staging"', "environment must be one of"),
        ('[deploy]\nprofiles = ["grafana"]', "unknown profile"),
        ('[deploy]\nprofiles = "llm"', "list of strings"),
        ('[deploy]\nbuild = "yes"', "build must be a bool"),
        ("[deploy]\nbiuld = true", "unknown key"),
        ("deploy = 3", "must be a table"),
        ("[deploy\n", "invalid TOML"),
    ],
)
def test_invalid_config_is_rejected(tmp_path, body, message):
    with pytest.raises(ConfigError, match=message):
        load_config(write_toml(tmp_path / "n.toml", body))


def test_project_config_beats_user_config(checkout, tmp_path):
    write_toml(tmp_path / "xdg" / "nemesis" / "nemesis.toml", '[deploy]\nenvironment = "dev"\n')
    cfg, project = load_effective_config(None, None, cwd=checkout)
    assert cfg.environment == "dev" and project == checkout
    write_toml(checkout / "nemesis.toml", '[deploy]\nenvironment = "prod"\n')
    cfg, _ = load_effective_config(None, None, cwd=checkout)
    assert cfg.environment == "prod" and cfg.source == checkout / "nemesis.toml"


def test_user_config_project_dir_used_outside_checkout(checkout, tmp_path):
    write_toml(tmp_path / "xdg" / "nemesis" / "nemesis.toml", f'[deploy]\nproject_dir = "{checkout}"\n')
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _, project = load_effective_config(None, None, cwd=elsewhere)
    assert project == checkout


def test_project_found_from_subdirectory(checkout):
    sub = checkout / "projects" / "cli"
    sub.mkdir(parents=True)
    _, project = load_effective_config(None, None, cwd=sub)
    assert project == checkout


def test_bad_project_dir_is_rejected(tmp_path, checkout):
    with pytest.raises(ConfigError, match="not a Nemesis checkout"):
        load_effective_config(None, tmp_path)


# --- command building ---


@pytest.mark.parametrize(
    ("action", "deployment", "expected_env", "expected_argv"),
    [
        ("start", Deployment("prod"), {}, ["-f", "compose.yaml", "up", "-d"]),
        ("start", Deployment("prod", build=True), {}, ["-f", "compose.yaml", "-f", "compose.prod.build.yaml", "up", "--build", "-d"]),
        ("start", Deployment("dev"), {}, ["up", "--build", "-d"]),
        (
            "stop",
            Deployment("prod", frozenset({"llm", "monitoring"}), phoenix_enabled=False),
            {"NEMESIS_MONITORING": "enabled", "PHOENIX_ENABLED": "false"},
            ["--profile", "monitoring", "--profile", "llm", "-f", "compose.yaml", "down"],
        ),
        ("clean", Deployment("dev", frozenset({"jupyter"})), {}, ["--profile", "jupyter", "down", "--volumes"]),
    ],
)  # fmt: skip
def test_compose_command(action, deployment, expected_env, expected_argv):
    env, argv = compose_command(action, deployment)
    assert env == expected_env
    assert argv == ["docker", "compose", *expected_argv]


def test_resolve_phoenix_enabled():
    assert compose.resolve_phoenix_enabled({}, None) is True
    assert compose.resolve_phoenix_enabled({}, False) is False
    assert compose.resolve_phoenix_enabled({"PHOENIX_ENABLED": "true"}, False) is True
    with pytest.raises(compose.CtlError):
        compose.resolve_phoenix_enabled({"PHOENIX_ENABLED": "1"}, None)


# --- commands ---


def test_stop_uses_config_profiles_and_flags_override(checkout, calls, monkeypatch):
    monkeypatch.chdir(checkout)
    write_toml(checkout / "nemesis.toml", '[deploy]\nenvironment = "prod"\nprofiles = ["monitoring", "jupyter"]\n')
    result = invoke("stop", "--no-jupyter", "--llm")
    assert result.exit_code == 0, result.output
    argv, env = calls[-1]
    assert argv == ["docker", "compose", "--profile", "monitoring", "--profile", "llm", "-f", "compose.yaml", "down"]
    assert env["NEMESIS_MONITORING"] == "enabled"


def test_cli_environment_overrides_config(checkout, calls):
    write_toml(checkout / "nemesis.toml", '[deploy]\nenvironment = "prod"\n')
    result = invoke("clean", "dev", "--project-dir", str(checkout))
    assert result.exit_code == 0, result.output
    assert calls[-1][0] == ["docker", "compose", "down", "--volumes"]


def test_missing_environment_is_a_usage_error(checkout, calls):
    result = invoke("stop", "--project-dir", str(checkout))
    assert result.exit_code == 2
    assert "Missing ENVIRONMENT" in result.output
    assert calls == []


def test_build_rejected_for_stop_and_clean(checkout, calls):
    for command in ("stop", "clean"):
        result = invoke(command, "prod", "--build", "--project-dir", str(checkout))
        assert result.exit_code == 2
        assert "cannot be used" in result.output
    assert calls == []


def test_config_build_ignored_by_stop(checkout, calls):
    write_toml(checkout / "nemesis.toml", "[deploy]\nbuild = true\n")
    assert invoke("stop", "prod", "--project-dir", str(checkout)).exit_code == 0


def test_start_without_env_file_fails(checkout, calls):
    result = invoke("start", "prod", "--project-dir", str(checkout))
    assert result.exit_code == 1
    assert "cp env.example .env" in result.output
    assert calls == []


def test_start_uses_config_build_and_phoenix(checkout, calls):
    (checkout / ".env").write_text('HASURA_ADMIN_SECRET="x"\nLITELLM_SALT_KEY="y"\nLITELLM_ADMIN_PASSWORD="z"\n')
    (checkout / "projects" / "frontend" / "public").mkdir(parents=True)
    write_toml(checkout / "nemesis.toml", '[deploy]\nbuild = true\nprofiles = ["llm"]\nphoenix_enabled = false\n')
    result = invoke("start", "prod", "--project-dir", str(checkout))
    assert result.exit_code == 0, result.output
    assert calls[1][0] == ["docker", "compose", "-f", "compose.base.yaml", "build"]
    argv, env = calls[-1]
    assert argv[-3:] == ["up", "--build", "-d"] and "compose.prod.build.yaml" in argv
    assert env["PHOENIX_ENABLED"] == "false"
    assert (checkout / "projects" / "frontend" / "public" / "version.json").read_text() == "{}"


def test_dry_run_runs_nothing_and_writes_nothing(checkout, calls):
    (checkout / ".env").write_text('HASURA_ADMIN_SECRET=""\n')
    result = invoke("start", "dev", "--monitoring", "--dry-run", "--project-dir", str(checkout))
    assert result.exit_code == 0, result.output
    assert calls == []
    assert (checkout / ".env").read_text() == 'HASURA_ADMIN_SECRET=""\n'
    assert "NEMESIS_MONITORING=enabled docker compose --profile monitoring up --build -d" in result.output
    assert "nothing was run" in result.output


def test_status_and_logs(checkout, calls):
    assert invoke("status", "prod", "--jupyter", "--project-dir", str(checkout)).exit_code == 0
    assert calls[-1][0] == ["docker", "compose", "--profile", "jupyter", "-f", "compose.yaml", "ps"]
    result = invoke("logs", "-e", "dev", "-f", "-n", "50", "web-api", "--project-dir", str(checkout))
    assert result.exit_code == 0, result.output
    assert calls[-1][0] == ["docker", "compose", "logs", "-f", "--tail", "50", "web-api"]
    assert calls[-1][1]["HASURA_ADMIN_SECRET"] == "unused-by-compose-down"


def test_config_init_and_show(checkout):
    result = invoke("config", "init", "--project-dir", str(checkout))
    assert result.exit_code == 0, result.output
    assert load_config(checkout / "nemesis.toml").environment == "prod"  # the example is valid
    assert invoke("config", "init", "--project-dir", str(checkout)).exit_code == 1  # no overwrite
    assert invoke("config", "init", "--force", "--project-dir", str(checkout)).exit_code == 0
    shown = invoke("config", "show", "--project-dir", str(checkout))
    assert shown.exit_code == 0
    assert "environment     = prod" in shown.output


def test_config_init_user(checkout, tmp_path):
    result = invoke("config", "init", "--user")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "xdg" / "nemesis" / "nemesis.toml").is_file()


def test_invalid_config_reported_cleanly(checkout):
    write_toml(checkout / "nemesis.toml", "[deploy]\nnope = 1\n")
    result = invoke("stop", "prod", "--project-dir", str(checkout))
    assert result.exit_code == 1
    assert "unknown key(s) in [deploy]: nope" in result.output
