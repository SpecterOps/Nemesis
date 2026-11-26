"""File-enrichment replicas: CPU sizing, the generated compose override, and how start/stop/clean/status use it."""

import shutil
import subprocess
from pathlib import Path

import pytest
from cli.ctl import sizing
from cli.ctl.compose import Controller
from cli.ctl.config import ConfigError, load_config
from cli.main import cli
from click.testing import CliRunner

# --- sizing rules ---


@pytest.mark.parametrize(
    ("cpus", "replicas"), [(1, 1), (2, 1), (4, 1), (5, 1), (6, 2), (7, 2), (8, 3), (9, 3), (10, 4), (16, 4), (64, 4)]
)
def test_auto_replicas(cpus, replicas):
    assert sizing.auto_replicas(cpus) == replicas


def test_detect_cpus_prefers_the_override(monkeypatch):
    monkeypatch.setattr(sizing.os, "process_cpu_count", lambda: 32)
    assert sizing.detect_cpus({"NEMESIS_CPUS": "6"}) == 6
    assert sizing.detect_cpus({}) == 32


@pytest.mark.parametrize("value", ["0", "-2", "eight", "1.5"])
def test_detect_cpus_rejects_bad_override(value):
    with pytest.raises(sizing.SizingError, match="NEMESIS_CPUS"):
        sizing.detect_cpus({"NEMESIS_CPUS": value})


@pytest.mark.parametrize(("value", "expected"), [("auto", None), (" AUTO ", None), ("3", 3), (2, 2), (1, 1)])
def test_parse_replicas(value, expected):
    assert sizing.parse_replicas(value) == expected


@pytest.mark.parametrize("value", [0, "0", -1, "two", "", "+2", True, 2.5, 2.0, None])
def test_parse_replicas_rejects(value):
    with pytest.raises(sizing.SizingError):
        sizing.parse_replicas(value)


def test_override_path_is_per_checkout_under_state_home(tmp_path):
    env = {"XDG_STATE_HOME": str(tmp_path / "state")}
    a = sizing.override_path(tmp_path / "a", env)
    assert a.is_relative_to(tmp_path / "state" / "nemesis" / "deployments")
    assert a == sizing.override_path(tmp_path / "a", env)
    assert a != sizing.override_path(tmp_path / "b", env)
    assert sizing.override_path(tmp_path / "a", {"HOME": str(tmp_path)}).is_relative_to(tmp_path / ".local" / "state")


def test_render_override_for_published_images(tmp_path):
    text = sizing.render_override(tmp_path, 3, build=False)
    compose_file = str(tmp_path.resolve() / "compose.yaml")
    for n in (2, 3):
        assert f'  file-enrichment-{n}:\n    extends: {{ file: "{compose_file}", service: file-enrichment }}' in text
        assert f"  file-enrichment-{n}-dapr:" in text
        assert f'network_mode: "service:file-enrichment-{n}"' in text
        assert f"      file-enrichment-{n}: {{ condition: service_started }}" in text
    assert "file-enrichment-4" not in text
    assert "image:" not in text  # the published image comes from compose.yaml


def test_render_override_reuses_the_locally_built_image(tmp_path):
    text = sizing.render_override(tmp_path, 2, build=True)
    assert "    image: nemesis-file-enrichment\n    pull_policy: never\n" in text


def test_render_override_needs_two_replicas(tmp_path):
    with pytest.raises(ValueError):
        sizing.render_override(tmp_path, 1, build=False)


MINI_COMPOSE = """\
name: nemesis
services:
  scheduler: { image: busybox }
  rabbitmq: { image: busybox }
  file-enrichment:
    image: ghcr.io/specterops/nemesis/file-enrichment:latest
    environment: { MAX_PARALLEL_WORKFLOWS: "5" }
    depends_on: { rabbitmq: { condition: service_healthy } }
  file-enrichment-dapr:
    image: daprio/daprd:1.19.2
    command: ["./daprd", "--app-id", "file-enrichment"]
    depends_on: { file-enrichment: { condition: service_started } }
    network_mode: "service:file-enrichment"
"""


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI unavailable")
def test_override_is_valid_compose(tmp_path):
    """`docker compose config` only parses and merges files: no daemon or network involved."""
    (tmp_path / "compose.yaml").write_text(MINI_COMPOSE)
    override = tmp_path / "state" / "compose.replicas.yaml"
    override.parent.mkdir()
    override.write_text(sizing.render_override(tmp_path, 3, build=True))
    proc = subprocess.run(
        ["docker", "compose", "-f", "compose.yaml", "-f", str(override), "config", "--format", "json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 and "is not a docker command" in proc.stderr:
        pytest.skip("docker compose plugin unavailable")
    assert proc.returncode == 0, proc.stderr
    import json

    services = json.loads(proc.stdout)["services"]
    assert services["file-enrichment-3"]["image"] == "nemesis-file-enrichment"
    assert services["file-enrichment-3"]["environment"] == {"MAX_PARALLEL_WORKFLOWS": "5"}
    dapr = services["file-enrichment-3-dapr"]
    assert dapr["command"] == ["./daprd", "--app-id", "file-enrichment"]  # same app ID: one logical app
    assert dapr["network_mode"] == "service:file-enrichment-3"
    assert set(dapr["depends_on"]) == {"file-enrichment-3", "scheduler", "rabbitmq"}


# --- commands ---


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    root = tmp_path / "nemesis"
    (root / "tools").mkdir(parents=True)
    (root / "compose.base.yaml").write_text("")
    (root / ".env").write_text('HASURA_ADMIN_SECRET="x"\nLITELLM_SALT_KEY="y"\nLITELLM_ADMIN_PASSWORD="z"\n')
    (root / "projects" / "frontend" / "public").mkdir(parents=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    for name in ("NEMESIS_CONFIG", "NEMESIS_PROJECT_DIR", "PHOENIX_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    return root


@pytest.fixture
def calls(monkeypatch):
    """Record docker calls; `fail` makes the compose up/down calls fail."""

    class Calls(list):
        state = {"fail": False}

    recorded = Calls()
    state = recorded.state

    def fake_runner(argv, env, cwd, quiet):
        if argv[0].endswith("generate-version.sh"):
            Path(argv[1]).write_text("{}")
            return 0
        if quiet:
            return 1  # `docker volume inspect` -> no existing data
        recorded.append(list(argv))
        is_main = any(word in argv for word in ("up", "down"))
        return 1 if state["fail"] and is_main else 0

    original_init = Controller.__init__

    def init(self, *args, **kwargs):
        kwargs["runner"] = fake_runner
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(Controller, "__init__", init)
    return recorded


def invoke(checkout, *args):
    return CliRunner().invoke(cli, [*args, "--project-dir", str(checkout)])


def override_for(checkout) -> Path:
    import os

    return sizing.override_path(checkout, os.environ)


def test_start_sizes_replicas_to_the_cpus(checkout, calls, monkeypatch):
    monkeypatch.setenv("NEMESIS_CPUS", "8")
    result = invoke(checkout, "start", "prod")
    assert result.exit_code == 0, result.output
    assert "File enrichment: 3 replicas, each with its own Dapr sidecar (sized for 8 CPUs)" in result.output
    path = override_for(checkout)
    assert calls[-1] == ["docker", "compose", "-f", "compose.yaml", "-f", str(path), "up", "-d"]
    text = path.read_text()
    assert "file-enrichment-3-dapr:" in text and "file-enrichment-4" not in text
    assert "image:" not in text  # published images


def test_start_with_build_reuses_the_built_image(checkout, calls, monkeypatch):
    monkeypatch.setenv("NEMESIS_CPUS", "6")
    assert invoke(checkout, "start", "prod", "--build").exit_code == 0
    assert "image: nemesis-file-enrichment" in override_for(checkout).read_text()
    assert calls[-1][-3:] == ["up", "--build", "-d"]


def test_one_replica_changes_nothing(checkout, calls):
    result = invoke(checkout, "start", "prod")  # 4 CPUs (conftest)
    assert result.exit_code == 0, result.output
    assert "File enrichment: 1 replica (sized for 4 CPUs)" in result.output
    assert calls[-1] == ["docker", "compose", "-f", "compose.yaml", "up", "-d"]
    assert not override_for(checkout).exists()


def test_fewer_replicas_removes_the_extra_ones(checkout, calls):
    assert invoke(checkout, "start", "prod", "--enrichment-replicas", "3").exit_code == 0
    assert invoke(checkout, "start", "prod", "--enrichment-replicas", "2").exit_code == 0
    path = override_for(checkout)
    assert calls[-1] == ["docker", "compose", "-f", "compose.yaml", "-f", str(path), "up", "-d", "--remove-orphans"]
    assert "file-enrichment-3" not in path.read_text()

    assert invoke(checkout, "start", "prod", "--enrichment-replicas", "1").exit_code == 0
    assert calls[-1] == ["docker", "compose", "-f", "compose.yaml", "up", "-d", "--remove-orphans"]
    assert not path.exists()


def test_replica_count_precedence(checkout, calls, monkeypatch):
    (checkout / "nemesis.toml").write_text("[deploy]\nenrichment_replicas = 2\n")
    invoke(checkout, "start", "prod")
    assert "file-enrichment-2:" in override_for(checkout).read_text()
    monkeypatch.setenv("NEMESIS_ENRICHMENT_REPLICAS", "3")  # env beats the file
    invoke(checkout, "start", "prod")
    assert "file-enrichment-3:" in override_for(checkout).read_text()
    result = invoke(checkout, "start", "prod", "--enrichment-replicas", "auto")  # flag beats env: 4 CPUs -> 1
    assert "1 replica (sized for 4 CPUs)" in result.output
    assert not override_for(checkout).exists()


@pytest.mark.parametrize("value", ["0", "many"])
def test_invalid_replica_count_is_a_usage_error(checkout, calls, value):
    result = invoke(checkout, "start", "prod", "--enrichment-replicas", value)
    assert result.exit_code == 2
    assert "--enrichment-replicas" in result.output
    assert calls == []


def test_invalid_cpu_override_fails_start(checkout, calls, monkeypatch):
    monkeypatch.setenv("NEMESIS_CPUS", "lots")
    result = invoke(checkout, "start", "prod")
    assert result.exit_code == 1
    assert "NEMESIS_CPUS must be a positive whole number" in result.output
    assert not any("up" in c for c in calls)


def test_dev_runs_one_instance(checkout, calls, monkeypatch):
    monkeypatch.setenv("NEMESIS_CPUS", "16")
    assert invoke(checkout, "start", "dev").exit_code == 0
    assert calls[-1] == ["docker", "compose", "up", "--build", "-d"]  # still loads compose.override.yaml
    assert not override_for(checkout).exists()
    result = invoke(checkout, "start", "dev", "--enrichment-replicas", "2")
    assert result.exit_code == 1
    assert "only supported in the prod environment" in result.output


def test_dry_run_writes_no_override(checkout, calls):
    result = invoke(checkout, "start", "prod", "--enrichment-replicas", "2", "--dry-run")
    assert result.exit_code == 0, result.output
    path = override_for(checkout)
    assert f"-f {path} up -d" in result.output
    assert "is not written" in result.output
    assert not path.exists()
    assert calls == []


@pytest.mark.parametrize("action", ["stop", "clean"])
def test_stop_and_clean_include_the_replicas_then_forget_them(checkout, calls, action):
    assert invoke(checkout, "start", "prod", "--enrichment-replicas", "2").exit_code == 0
    path = override_for(checkout)
    assert invoke(checkout, action, "prod").exit_code == 0
    assert calls[-1][:6] == ["docker", "compose", "-f", "compose.yaml", "-f", str(path)]
    assert not path.exists()


def test_failed_stop_keeps_the_replicas_file(checkout, calls):
    assert invoke(checkout, "start", "prod", "--enrichment-replicas", "2").exit_code == 0
    calls.state["fail"] = True
    assert invoke(checkout, "stop", "prod").exit_code != 0
    assert override_for(checkout).exists()  # the replicas may still be running


def test_status_and_logs_include_the_replicas(checkout, calls):
    assert invoke(checkout, "start", "prod", "--enrichment-replicas", "2").exit_code == 0
    path = str(override_for(checkout))
    invoke(checkout, "status", "prod")
    assert calls[-1] == ["docker", "compose", "-f", "compose.yaml", "-f", path, "ps"]
    CliRunner().invoke(cli, ["logs", "-e", "prod", "file-enrichment-2", "--project-dir", str(checkout)])
    assert calls[-1] == ["docker", "compose", "-f", "compose.yaml", "-f", path, "logs", "file-enrichment-2"]
    invoke(checkout, "status", "dev")
    assert calls[-1] == ["docker", "compose", "ps"]


def test_config_key(tmp_path, checkout):
    path = tmp_path / "n.toml"
    path.write_text('[deploy]\nenrichment_replicas = "auto"\n')
    assert load_config(path).enrichment_replicas == "auto"
    path.write_text("[deploy]\nenrichment_replicas = 0\n")
    with pytest.raises(ConfigError, match="enrichment_replicas"):
        load_config(path)
    (checkout / "nemesis.toml").write_text("[deploy]\nenrichment_replicas = 3\n")
    shown = CliRunner().invoke(cli, ["config", "show", "--project-dir", str(checkout)])
    assert "enrichment_replicas = 3 (prod)" in shown.output
