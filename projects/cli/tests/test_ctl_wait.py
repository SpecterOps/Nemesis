"""`start --wait`: poll `docker compose ps` until services are ready, failed, or the timeout passes."""

import json

import pytest
from cli.ctl import health
from cli.ctl.compose import Controller, CtlError, Deployment
from cli.ctl.config import ConfigError, load_config
from cli.main import cli
from click.testing import CliRunner


def ps(*containers: tuple[str, str, str, int]) -> str:
    """NDJSON like Compose >= 2.21: (service, state, health, exit_code) per container."""
    return "\n".join(
        json.dumps({"Service": s, "State": st, "Health": h, "ExitCode": ec, "Name": f"nemesis-{s}-1"})
        for s, st, h, ec in containers
    )


# --- parsing and classification ---


def test_parse_ndjson_and_array():
    line = ps(("web-api", "running", "healthy", 0))
    expected = [health.Container("web-api", "running", "healthy", 0)]
    assert health.parse_ps(line) == expected
    assert health.parse_ps(f"[{line}]") == expected
    assert health.parse_ps("") == []
    assert health.parse_ps("\n\n") == []


def test_parse_rejects_garbage():
    with pytest.raises(ValueError):
        health.parse_ps("not json")


def test_classify():
    r = health.classify(
        health.parse_ps(
            ps(
                ("healthy", "running", "healthy", 0),
                ("no-check", "running", "", 0),
                ("init", "exited", "", 0),
                ("booting", "running", "starting", 0),
                ("sick", "running", "unhealthy", 0),
                ("looping", "restarting", "", 1),
                ("new", "created", "", 0),
                ("crashed", "exited", "", 2),
                ("gone", "dead", "", 0),
            )
        )
    )
    assert r.ready == ["healthy", "init", "no-check"]
    assert r.pending == {"booting": "starting", "looping": "restarting", "new": "created", "sick": "unhealthy"}
    assert r.failed == {"crashed": "exited 2", "gone": "dead"}
    assert r.total == 9 and not r.done


def test_summarize_truncates():
    r = health.Readiness(ready=["a"], pending={f"s{i}": "starting" for i in range(10)})
    line = health.summarize(r, limit=3)
    assert line.startswith("1/11 ready; waiting on: s0 (starting), s1 (starting), s2 (starting), +7 more")
    assert health.summarize(health.Readiness(ready=["a", "b"])) == "2/2 ready"


# --- polling ---


def _services_in(output: str) -> list[str]:
    try:
        return [c.service for c in health.parse_ps(output)]
    except ValueError:
        return []


class FakeDocker:
    """Returns scripted `ps` outputs in turn (repeating the last), with a fake clock.

    `config --services` lists SERVICES, by default every service the scripted outputs mention.
    """

    def __init__(self, outputs: list[str | tuple[int, str]], services: list[str] | None = None, config_rc: int = 0):
        self.outputs = outputs
        self.calls: list[list[str]] = []  # ps calls
        self.config_calls: list[list[str]] = []
        self.now = 0.0
        self.config_rc = config_rc
        if services is None:
            services = sorted({m for out in outputs if isinstance(out, str) for m in _services_in(out)})
        self.services = services

    def capturer(self, argv, env, cwd):
        if "config" in argv:
            self.config_calls.append(list(argv))
            return self.config_rc, "\n".join(self.services) + "\n"
        self.calls.append(list(argv))
        out = self.outputs[min(len(self.calls), len(self.outputs)) - 1]
        return out if isinstance(out, tuple) else (0, out)

    def sleep(self, seconds):
        self.now += seconds


def controller(tmp_path, fake: FakeDocker, messages: list[str]) -> Controller:
    return Controller(
        tmp_path,
        environ={},
        capturer=fake.capturer,
        clock=lambda: fake.now,
        sleep=fake.sleep,
        echo=messages.append,
    )


def test_waits_until_ready_and_reports_progress_once_per_change(tmp_path):
    starting = ps(("db", "running", "starting", 0), ("init", "running", "", 0))
    fake = FakeDocker(
        [
            "",
            starting,
            starting,
            ps(("db", "running", "healthy", 0), ("init", "exited", "", 0)),
        ]
    )
    messages: list[str] = []
    controller(tmp_path, fake, messages).wait_until_ready(
        Deployment("prod", frozenset({"llm"}), wait=True, wait_timeout=60)
    )
    assert fake.calls[0] == [
        "docker",
        "compose",
        "--profile",
        "llm",
        "-f",
        "compose.yaml",
        "ps",
        "--all",
        "--format",
        "json",
    ]
    progress = messages[1:]
    assert progress == ["no containers yet", "1/2 ready; waiting on: db (starting)", "2/2 ready"]


def test_fails_fast_when_a_service_exits_with_an_error(tmp_path):
    fake = FakeDocker([ps(("db", "running", "starting", 0), ("web-api", "exited", "", 1))])
    with pytest.raises(CtlError, match=r"web-api \(exited 1\)"):
        controller(tmp_path, fake, []).wait_until_ready(Deployment("dev", wait=True, wait_timeout=60))
    assert len(fake.calls) == 1


def test_times_out_listing_pending_services(tmp_path):
    fake = FakeDocker([ps(("db", "running", "healthy", 0), ("agents", "running", "unhealthy", 0))])
    with pytest.raises(CtlError, match=r"Timed out after 10s; 1/2 ready; waiting on: agents \(unhealthy\)"):
        controller(tmp_path, fake, []).wait_until_ready(Deployment("dev", wait=True, wait_timeout=10))
    assert fake.now >= 10
    assert len(fake.calls) == 6  # t=0,2,4,6,8,10


def test_ps_failure_is_an_error(tmp_path):
    fake = FakeDocker([(1, "")])
    with pytest.raises(CtlError, match="exit 1"):
        controller(tmp_path, fake, []).wait_until_ready(Deployment("dev", wait=True))


def test_unparseable_ps_output_is_an_error(tmp_path):
    fake = FakeDocker(["{broken"])
    with pytest.raises(CtlError, match="Could not parse"):
        controller(tmp_path, fake, []).wait_until_ready(Deployment("dev", wait=True))


def test_ignores_containers_outside_the_deployment(tmp_path):
    """An exited container from a profile this start didn't enable (e.g. an old --monitoring run) doesn't count."""
    fake = FakeDocker(
        [ps(("db", "running", "healthy", 0), ("loki", "exited", "", 1), ("grafana", "running", "starting", 0))],
        services=["db"],
    )
    messages: list[str] = []
    controller(tmp_path, fake, messages).wait_until_ready(Deployment("prod", wait=True, wait_timeout=60))
    assert messages[-1] == "1/1 ready"
    assert fake.config_calls == [["docker", "compose", "-f", "compose.yaml", "config", "--services"]]


def test_config_failure_is_an_error(tmp_path):
    fake = FakeDocker([ps(("db", "running", "healthy", 0))], config_rc=1)
    with pytest.raises(CtlError, match="`docker compose config` failed"):
        controller(tmp_path, fake, []).wait_until_ready(Deployment("dev", wait=True))
    assert fake.calls == []


def test_dry_run_does_not_poll(tmp_path):
    fake = FakeDocker([])
    c = controller(tmp_path, fake, [])
    c.dry_run = True
    c.wait_until_ready(Deployment("dev", wait=True))
    assert fake.calls == [] and fake.config_calls == []


# --- start --wait from the command line and nemesis.toml ---


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    root = tmp_path / "nemesis"
    (root / "tools").mkdir(parents=True)
    (root / "projects" / "frontend" / "public").mkdir(parents=True)
    (root / "compose.base.yaml").write_text("")
    (root / ".env").write_text('HASURA_ADMIN_SECRET="x"\nLITELLM_SALT_KEY="y"\nLITELLM_ADMIN_PASSWORD="z"\n')
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("NEMESIS_CONFIG", raising=False)
    return root


@pytest.fixture
def waits(monkeypatch):
    """Fake docker for `start`, recording each wait_until_ready call's deployment."""
    seen: list[Deployment] = []

    def runner(argv, env, cwd, quiet):
        if argv[0].endswith("generate-version.sh"):
            (cwd / "version.json").write_text("{}")
        return 1 if quiet else 0

    original_init = Controller.__init__

    def init(self, *args, **kwargs):
        original_init(self, *args, runner=runner, **kwargs)

    monkeypatch.setattr(Controller, "__init__", init)
    monkeypatch.setattr(Controller, "wait_until_ready", lambda self, d: seen.append(d))
    return seen


def start(checkout, *args):
    return CliRunner().invoke(cli, ["start", "prod", "--project-dir", str(checkout), *args])


def test_start_does_not_wait_by_default(checkout, waits):
    result = start(checkout)
    assert result.exit_code == 0, result.output
    assert waits == []
    assert "Services are up and running." in result.output


def test_start_wait_flag(checkout, waits):
    result = start(checkout, "--wait", "--wait-timeout", "90")
    assert result.exit_code == 0, result.output
    assert [(d.wait, d.wait_timeout) for d in waits] == [(True, 90)]
    assert "All services are up and healthy." in result.output


def test_start_wait_from_config_and_no_wait_override(checkout, waits):
    (checkout / "nemesis.toml").write_text("[deploy]\nwait = true\nwait_timeout = 300\n")
    assert start(checkout).exit_code == 0
    assert waits[-1].wait_timeout == 300
    assert start(checkout, "--no-wait").exit_code == 0
    assert len(waits) == 1


def test_start_reports_wait_failure(checkout, monkeypatch, waits):
    def fail(self, d):
        raise CtlError("Service(s) failed to start: web-api (exited 1)")

    monkeypatch.setattr(Controller, "wait_until_ready", fail)
    result = start(checkout, "--wait")
    assert result.exit_code == 1
    assert "web-api (exited 1)" in result.output


def test_wait_timeout_must_be_positive(checkout, waits):
    assert start(checkout, "--wait", "--wait-timeout", "0").exit_code == 2


@pytest.mark.parametrize("value", ["0", "-5", "true", '"60"'])
def test_config_rejects_bad_wait_timeout(tmp_path, value):
    path = tmp_path / "n.toml"
    path.write_text(f"[deploy]\nwait_timeout = {value}\n")
    with pytest.raises(ConfigError, match="wait_timeout"):
        load_config(path)
