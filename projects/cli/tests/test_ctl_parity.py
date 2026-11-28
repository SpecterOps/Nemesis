"""`cli start/stop/clean` and tools/nemesis-ctl.sh must make the same docker calls and leave the same .env.

Both run against a scratch copy of the repo's tools/ with a stub `docker` on PATH that records each call
and the environment variables compose would interpolate.
"""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from cli.main import cli
from click.testing import CliRunner

REPO = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or not (REPO / "tools" / "nemesis-ctl.sh").is_file(),
    reason="bash or tools/nemesis-ctl.sh unavailable",
)

RECORDED_VARS = [
    "NEMESIS_MONITORING",
    "PHOENIX_ENABLED",
    "HASURA_ADMIN_SECRET",
    "LITELLM_SALT_KEY",
    "LITELLM_ADMIN_PASSWORD",
    "POSTGRES_USER_URLENC",
    "POSTGRES_PASSWORD_URLENC",
    "RABBITMQ_USER_URLENC",
    "RABBITMQ_PASSWORD_URLENC",
    "NEMESIS_LOGIN_HTPASSWD",
    "NEMESIS_TLS_CERT_SHA256",
]

STUB_DOCKER = (
    """#!/bin/bash
if [ "$1" = volume ]; then
  [ "${STUB_VOLUME_EXISTS:-false}" = true ] && exit 0 || exit 1
fi
{
  printf 'docker'; printf ' %q' "$@"; printf '\\n'
"""
    + "".join(f'  printf "  {v}=%q\\n" "${{{v}-<unset>}}"\n' for v in RECORDED_VARS)
    + """} >> "$STUB_LOG"
exit "${STUB_EXIT:-0}"
"""
)

ENV_TEMPLATE = """\
RABBITMQ_PASSWORD="Qw@rty 123"
RABBITMQ_USER="nemesis"
POSTGRES_PASSWORD="Qwerty12345"
POSTGRES_USER="nemesis"
HASURA_ADMIN_SECRET=""
LITELLM_ADMIN_PASSWORD="{litellm_password}"
LITELLM_SALT_KEY=""
"""


def make_checkout(root: Path, env_content: str | None) -> Path:
    (root / "tools" / "lib").mkdir(parents=True)
    shutil.copy(REPO / "tools" / "nemesis-ctl.sh", root / "tools")
    shutil.copy(REPO / "tools" / "lib" / "env_secrets.sh", root / "tools" / "lib")
    shutil.copy(REPO / "tools" / "lib" / "tls_cert.sh", root / "tools" / "lib")
    gen = root / "tools" / "generate-version.sh"
    gen.write_text('#!/bin/bash\necho "{}" > "$1"\n')
    (root / "compose.base.yaml").write_text("")
    (root / "projects" / "frontend" / "public").mkdir(parents=True)
    if env_content is not None:
        (root / ".env").write_text(env_content)
        (root / ".env").chmod(0o600)
    for script in (gen, root / "tools" / "nemesis-ctl.sh"):
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return root


@pytest.fixture
def stub_path(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(STUB_DOCKER)
    docker.chmod(0o755)
    return bin_dir


def mask_secrets(text: str, mask_logins: bool = True) -> str:
    """Random secrets differ between runs (and so does the login hashed from a random password); keep their shape."""
    text = re.sub(r"[0-9a-f]{48}", "<random48>", text)
    # Each checkout gets its own certificate
    text = re.sub(r"(?:[0-9A-F]{2}\\?:){31}[0-9A-F]{2}", "<cert-sha256>", text)
    if not mask_logins:
        return text
    # printf %q escapes the $ signs of the hash in the stub log
    return re.sub(r"(\\?\$apr1\\?\$)[0-9a-f]{8}(\\?\$)[./0-9A-Za-z]{22}", r"\1<salt>\2<hash>", text)


def run_both(tmp_path, stub_path, args, *, env_content, extra_env=None, mask_logins=True):
    results = {}
    for impl in ("bash", "python"):
        checkout = make_checkout(tmp_path / impl, env_content)
        log = tmp_path / f"{impl}.log"
        log.touch()
        env = {
            "PATH": f"{stub_path}:/usr/bin:/bin",
            "HOME": str(tmp_path),
            "XDG_CONFIG_HOME": str(tmp_path / "xdg"),
            "STUB_LOG": str(log),
            # Replicas are a CLI-only feature (sized to the CPUs); with one, the CLI must match the script exactly
            "NEMESIS_ENRICHMENT_REPLICAS": "1",
            "XDG_STATE_HOME": str(tmp_path / "state"),
            **(extra_env or {}),
        }
        if impl == "bash":
            proc = subprocess.run(
                [str(checkout / "tools" / "nemesis-ctl.sh"), *args], env=env, capture_output=True, text=True
            )
            rc = proc.returncode
        else:
            saved = os.environ.copy()
            os.environ.clear()
            os.environ.update(env)
            try:
                result = CliRunner().invoke(cli, [*args, "--project-dir", str(checkout)])
            finally:
                os.environ.clear()
                os.environ.update(saved)
            rc = result.exit_code
        env_file = checkout / ".env"
        results[impl] = {
            "rc": rc,
            "calls": mask_secrets(log.read_text(), mask_logins),
            "env": mask_secrets(env_file.read_text()) if env_file.exists() else None,
            "version": (checkout / "projects" / "frontend" / "public" / "version.json").exists(),
        }
    return results["bash"], results["python"]


@pytest.mark.parametrize(
    "args",
    [
        ["start", "prod"],
        ["start", "prod", "--build"],
        ["start", "dev"],
        ["start", "prod", "--monitoring", "--jupyter", "--llm"],
        ["start", "dev", "--llm"],
        ["stop", "prod"],
        ["stop", "prod", "--monitoring", "--jupyter", "--llm"],
        ["clean", "dev", "--monitoring"],
        ["clean", "prod", "--llm"],
    ],
    ids=" ".join,
)
@pytest.mark.parametrize("volume_exists", [False, True], ids=["fresh", "existing-data"])
def test_same_docker_calls_and_env(tmp_path, stub_path, args, volume_exists):
    bash, py = run_both(
        tmp_path,
        stub_path,
        args,
        env_content=ENV_TEMPLATE.format(litellm_password="oldpw"),
        extra_env={"STUB_VOLUME_EXISTS": str(volume_exists).lower()},
    )
    assert bash["rc"] == 0
    assert py == bash
    assert bash["calls"]  # the stub was actually reached


def test_same_result_with_phoenix_env(tmp_path, stub_path):
    env = ENV_TEMPLATE.format(litellm_password="")
    bash, py = run_both(
        tmp_path, stub_path, ["start", "prod", "--llm"], env_content=env, extra_env={"PHOENIX_ENABLED": "false"}
    )
    assert py == bash
    assert "PHOENIX_ENABLED=false" in bash["calls"]


def test_same_login_hash_for_a_set_password(tmp_path, stub_path):
    """With NEMESIS_PASSWORD (and NEMESIS_USER) in .env, both hash the login identically (compared unmasked)."""
    env = ENV_TEMPLATE.format(litellm_password="x") + 'NEMESIS_USER="alice"\nNEMESIS_PASSWORD="correct horse battery"\n'
    bash, py = run_both(tmp_path, stub_path, ["start", "prod"], env_content=env, mask_logins=False)
    assert bash["rc"] == 0 and py == bash
    from cli.ctl.envfile import nemesis_login_htpasswd

    expected = nemesis_login_htpasswd(tmp_path / "python" / ".env", {})
    assert expected.startswith("alice:$apr1$")
    assert "NEMESIS_LOGIN_HTPASSWD=" + expected.replace("$", "\\$") in bash["calls"]


def test_both_generate_the_login_and_supply_a_placeholder_on_stop(tmp_path, stub_path):
    env = ENV_TEMPLATE.format(litellm_password="x")
    bash, py = run_both(tmp_path, stub_path, ["start", "prod"], env_content=env)
    assert py == bash
    assert 'NEMESIS_PASSWORD="<random48>"' in bash["env"]
    assert "NEMESIS_LOGIN_HTPASSWD=n:" in bash["calls"]
    bash, py = run_both(tmp_path / "stop", stub_path, ["stop", "prod"], env_content=env)
    assert py == bash
    assert "NEMESIS_LOGIN_HTPASSWD=unused-by-compose-down" in bash["calls"]


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_both_create_the_same_certificate(tmp_path, stub_path):
    env = ENV_TEMPLATE.format(litellm_password="x") + 'NEMESIS_URL="https://nemesis.corp.local:7443/"\n'
    bash, py = run_both(tmp_path, stub_path, ["start", "prod"], env_content=env)
    assert py == bash and bash["rc"] == 0
    described = []
    for impl in ("bash", "python"):
        crt = tmp_path / impl / "infra" / "traefik" / "certs" / "server.crt"
        described.append(
            subprocess.run(
                ["openssl", "x509", "-in", str(crt), "-noout", "-subject", "-ext", "subjectAltName"],
                capture_output=True, text=True, check=True,
            ).stdout
        )  # fmt: skip
        assert (crt.parent / "server.key").stat().st_mode & 0o777 == 0o600
    assert described[0] == described[1]
    assert "CN = nemesis.corp.local" in described[0] and "DNS:nemesis.corp.local" in described[0]


def test_both_refuse_invalid_phoenix(tmp_path, stub_path):
    bash, py = run_both(
        tmp_path,
        stub_path,
        ["start", "prod", "--llm"],
        env_content=ENV_TEMPLATE.format(litellm_password=""),
        extra_env={"PHOENIX_ENABLED": "yes"},
    )
    assert bash["rc"] != 0 and py["rc"] != 0
    assert bash["calls"] == py["calls"] == ""


def test_both_refuse_start_without_env_file(tmp_path, stub_path):
    bash, py = run_both(tmp_path, stub_path, ["start", "prod"], env_content=None)
    assert bash["rc"] != 0 and py["rc"] != 0
    assert bash["calls"] == py["calls"] == ""


def test_both_stop_without_env_file(tmp_path, stub_path):
    bash, py = run_both(tmp_path, stub_path, ["stop", "prod"], env_content=None)
    assert bash["rc"] == py["rc"] == 0
    assert py == bash
    assert "HASURA_ADMIN_SECRET=unused-by-compose-down" in py["calls"]


def test_both_refuse_dollar_in_credentials(tmp_path, stub_path):
    env = ENV_TEMPLATE.format(litellm_password="").replace("Qwerty12345", "Qwer$ty")
    bash, py = run_both(tmp_path, stub_path, ["start", "prod"], env_content=env)
    assert bash["rc"] != 0 and py["rc"] != 0
    assert bash["calls"] == py["calls"] == ""


def test_both_propagate_docker_failure(tmp_path, stub_path):
    bash, py = run_both(tmp_path, stub_path, ["stop", "prod"], env_content="", extra_env={"STUB_EXIT": "3"})
    assert bash["rc"] == py["rc"] == 3
