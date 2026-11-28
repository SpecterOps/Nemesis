"""TLS certificate per deployment: created when missing, kept when valid, our own renewed before it expires, a user's
never replaced. Uses the real openssl command."""

import shutil
import subprocess
from pathlib import Path

import pytest
from cli.ctl import tlscert

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")


def openssl(*args: str) -> str:
    return subprocess.run(["openssl", *args], capture_output=True, text=True, check=True).stdout


def make_cert(directory: Path, org: str, days: int) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    openssl(
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", str(days),
        "-subj", f"/O={org}/CN=x", "-keyout", str(directory / "server.key"), "-out", str(directory / "server.crt"),
    )  # fmt: skip


def info(directory: Path) -> str:
    return openssl("x509", "-in", str(directory / "server.crt"), "-noout", "-subject", "-ext", "subjectAltName")


@pytest.fixture
def env(tmp_path):
    path = tmp_path / ".env"
    path.write_text('NEMESIS_URL="https://nemesis.corp.local:7443/"\n')
    return path


def run(cert_dir, env, environ=None):
    messages: list[str] = []
    tlscert.ensure_tls_certificate(cert_dir, env, environ or {}, messages.append)
    return messages


def test_creates_a_certificate_for_the_nemesis_host(tmp_path, env):
    certs = tmp_path / "infra" / "traefik" / "certs"
    messages = run(certs, env)
    assert "Created a self-signed TLS certificate for nemesis.corp.local" in messages[0]
    text = info(certs)
    assert "O = Nemesis self-signed" in text and "CN = nemesis.corp.local" in text
    assert "DNS:localhost, IP Address:127.0.0.1, DNS:nemesis.corp.local" in text
    assert (certs / "server.key").stat().st_mode & 0o777 == 0o600
    assert not list(certs.glob("*.new"))


def test_keeps_a_valid_certificate(tmp_path, env):
    certs = tmp_path / "certs"
    run(certs, env)
    before = (certs / "server.crt").read_bytes()
    assert run(certs, env) == []
    assert (certs / "server.crt").read_bytes() == before


def test_renews_its_own_certificate_before_it_expires(tmp_path, env):
    certs = tmp_path / "certs"
    make_cert(certs, "Nemesis self-signed", 5)
    messages = run(certs, env)
    assert messages[0].startswith("Renewing the self-signed TLS certificate")
    still_valid_in_300_days = [
        "openssl",
        "x509",
        "-in",
        str(certs / "server.crt"),
        "-noout",
        "-checkend",
        str(300 * 86400),
    ]
    assert subprocess.run(still_valid_in_300_days, capture_output=True).returncode == 0


def test_never_replaces_a_users_certificate(tmp_path, env, capsys):
    certs = tmp_path / "certs"
    make_cert(certs, "Example Corp", 5)
    before = (certs / "server.crt").read_bytes()
    assert run(certs, env) == []
    assert (certs / "server.crt").read_bytes() == before
    assert "expires within 30 days" in capsys.readouterr().err


def test_openssl_failure_is_an_error(tmp_path, env, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "nothing-here"))
    with pytest.raises(tlscert.CertError, match="could not create a TLS certificate"):
        run(tmp_path / "certs", env)
    assert not (tmp_path / "certs" / "server.key").exists()


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://nemesis.corp.local:7443/", "nemesis.corp.local"),
        ("https://10.1.2.3:7443", "10.1.2.3"),
        ("https://user:pw@host.example/path", "host.example"),
        ("https://[fd00::1]:7443/", "fd00::1"),
        ("nemesis.local", "nemesis.local"),
        ("", ""),
    ],
)
def test_nemesis_url_host(tmp_path, url, host):
    env = tmp_path / ".env"
    env.write_text("")
    assert tlscert.nemesis_url_host(env, {"NEMESIS_URL": url}) == host


@pytest.mark.parametrize(
    ("url", "san"), [("https://10.1.2.3:7443/", "IP Address:10.1.2.3"), ("", "DNS:localhost, IP Address:127.0.0.1\n")]
)
def test_ip_hosts_become_ip_names(tmp_path, url, san):
    env = tmp_path / ".env"
    env.write_text("")
    run(tmp_path / "certs", env, {"NEMESIS_URL": url})
    assert info(tmp_path / "certs").endswith(san) or san in info(tmp_path / "certs")
