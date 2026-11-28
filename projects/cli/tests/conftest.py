import pytest


@pytest.fixture(autouse=True)
def isolated_deployment_state(request, tmp_path, monkeypatch):
    """`start` sizes file-enrichment replicas to the CPUs and writes their override under $XDG_STATE_HOME: keep the
    deployment-command tests independent of the machine (4 CPUs -> 1 replica, the behaviour before replicas) and out
    of the real state directory."""
    monkeypatch.setenv("NEMESIS_CPUS", "4")
    # submit/monitor require the Nemesis password (no public default any more)
    monkeypatch.setenv("NEMESIS_PASSWORD", "test-password")
    monkeypatch.delenv("NEMESIS_ENRICHMENT_REPLICAS", raising=False)
    if request.module.__name__.rpartition(".")[2].startswith("test_ctl_"):
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
