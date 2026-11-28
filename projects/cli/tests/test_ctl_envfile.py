"""cli.ctl.envfile must read and write .env exactly like tools/lib/env_secrets.sh."""

import shutil
import subprocess
from pathlib import Path

import pytest
from cli.ctl import envfile

REPO = Path(__file__).resolve().parents[3]
ENV_SECRETS_SH = REPO / "tools" / "lib" / "env_secrets.sh"

needs_bash = pytest.mark.skipif(
    shutil.which("bash") is None or not ENV_SECRETS_SH.is_file(), reason="bash or env_secrets.sh unavailable"
)


def bash(script: str, *args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["bash", "-c", f'set -euo pipefail; source "{ENV_SECRETS_SH}"; {script}', "bash", *args],
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": "/usr/bin:/bin", **(env or {})},
    )
    return result.stdout


VALUE_LINES = [
    "plain",
    '"quoted"',
    "'single'",
    '"with # hash" # comment',
    "unquoted # comment",
    "unquoted#nocomment",
    "  padded  ",
    " # only a comment",
    "",
    '"a"b"',
    '"x" trailing',
    "p@ss:w/rd%",
    "tab\t# comment",
    "'it''s'",
    "sk-abc=def",
]


@needs_bash
@pytest.mark.parametrize("raw", VALUE_LINES)
def test_env_file_value_matches_bash(tmp_path, raw):
    env = tmp_path / ".env"
    env.write_text(f"OTHER=1\nNAME={raw}\n")
    expected = bash('env_file_value "$1" NAME', str(env)).removesuffix("\n")
    assert envfile.env_file_value(env, "NAME") == expected


@needs_bash
def test_last_assignment_wins_and_indented_lines_count(tmp_path):
    env = tmp_path / ".env"
    env.write_text('NAME="first"\n  NAME=second\n# NAME=commented\nNAMEX=other\n')
    assert envfile.env_file_value(env, "NAME") == "second"
    assert bash('env_file_value "$1" NAME', str(env)) == "second\n"


def test_missing_name_or_file_is_empty(tmp_path):
    env = tmp_path / ".env"
    assert envfile.env_file_value(env, "NAME") == ""
    env.write_text("OTHER=1\n")
    assert envfile.env_file_value(env, "NAME") == ""


@needs_bash
@pytest.mark.parametrize(
    "content",
    ["A=1\nNAME=old\nB=2\n", "A=1\n  NAME=old\nNAME=again\n", "A=1\n", "A=1", ""],
    ids=["rewrite", "rewrite-all", "append", "append-no-newline", "empty"],
)
def test_set_env_file_value_matches_bash(tmp_path, content):
    py, sh = tmp_path / "py.env", tmp_path / "sh.env"
    py.write_text(content)
    sh.write_text(content)
    envfile.set_env_file_value(py, "NAME", "new value")
    bash('set_env_file_value "$1" NAME "new value"', str(sh))
    assert py.read_text() == sh.read_text()
    assert py.stat().st_mode & 0o777 == 0o600


@needs_bash
@pytest.mark.parametrize("value", ["simple", "p@ss:w/rd #1", "ünïcode", "a b+c~d.e_f-g"])
def test_url_encode_matches_bash(value):
    assert envfile.url_encode(value) == bash('url_encode "$1"', value)


def test_url_encoded_credentials_prefers_environment(tmp_path):
    env = tmp_path / ".env"
    env.write_text('POSTGRES_USER="nemesis"\nPOSTGRES_PASSWORD="p@ss word"\n')
    result = envfile.url_encoded_credentials(
        env, ["POSTGRES_USER", "POSTGRES_PASSWORD", "RABBITMQ_USER"], {"POSTGRES_USER": "from:env"}
    )
    assert result == {"POSTGRES_USER_URLENC": "from%3Aenv", "POSTGRES_PASSWORD_URLENC": "p%40ss%20word"}


def test_url_encoded_credentials_rejects_dollar(tmp_path):
    env = tmp_path / ".env"
    env.write_text('POSTGRES_PASSWORD="a$b"\nRABBITMQ_PASSWORD="c$d"\n')
    with pytest.raises(envfile.EnvFileError, match="POSTGRES_PASSWORD RABBITMQ_PASSWORD"):
        envfile.url_encoded_credentials(env, ["POSTGRES_PASSWORD", "RABBITMQ_PASSWORD"], {})


def test_ensure_random_env_secret_generates_only_when_unset(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text('HASURA_ADMIN_SECRET=""\nKEEP="mine"\n')
    envfile.ensure_random_env_secret(env, "HASURA_ADMIN_SECRET", {})
    envfile.ensure_random_env_secret(env, "KEEP", {})
    value = envfile.env_file_value(env, "HASURA_ADMIN_SECRET")
    assert len(value) == 48 and int(value, 16) >= 0
    assert envfile.env_file_value(env, "KEEP") == "mine"
    assert value not in capsys.readouterr().out  # never printed


def test_ensure_random_env_secret_keeps_and_warns_on_public_default(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text('HASURA_ADMIN_SECRET="pass456"\n')
    envfile.ensure_random_env_secret(env, "HASURA_ADMIN_SECRET", {}, ["pass456"])
    assert envfile.env_file_value(env, "HASURA_ADMIN_SECRET") == "pass456"
    assert "public default" in capsys.readouterr().err


def test_ensure_random_env_secret_respects_environment_and_missing_file(tmp_path):
    env = tmp_path / ".env"
    envfile.ensure_random_env_secret(env, "X", {})
    assert not env.exists()
    env.write_text("")
    envfile.ensure_random_env_secret(env, "X", {"X": "from-shell"})
    assert env.read_text() == ""


@pytest.mark.parametrize(
    ("existing_data", "password", "expected"),
    [(True, "secret", "sk-secret"), (True, "", "sk-admin123"), (False, "secret", None)],
)
def test_ensure_litellm_salt_key(tmp_path, existing_data, password, expected):
    env = tmp_path / ".env"
    env.write_text(f'LITELLM_ADMIN_PASSWORD="{password}"\nLITELLM_SALT_KEY=""\n')
    envfile.ensure_litellm_salt_key(env, existing_data, {})
    salt = envfile.env_file_value(env, "LITELLM_SALT_KEY")
    if expected:
        assert salt == expected
    else:
        assert salt.startswith("sk-") and len(salt) == 51


def test_ensure_litellm_salt_key_keeps_existing(tmp_path):
    env = tmp_path / ".env"
    env.write_text('LITELLM_SALT_KEY="sk-set"\n')
    envfile.ensure_litellm_salt_key(env, False, {})
    assert envfile.env_file_value(env, "LITELLM_SALT_KEY") == "sk-set"


def test_placeholders_only_for_unset(tmp_path):
    env = tmp_path / ".env"
    env.write_text('A="set"\nB=""\n')
    assert envfile.placeholders_for_compose_down(env, ["A", "B", "C"], {"C": "shell"}) == {
        "B": "unused-by-compose-down"
    }
    assert envfile.placeholders_for_compose_down(tmp_path / "missing", ["A"], {}) == {"A": "unused-by-compose-down"}


def test_warn_if_env_file_shared(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text("")
    env.chmod(0o644)
    envfile.warn_if_env_file_shared(env)
    assert "mode 644" in capsys.readouterr().err
    env.chmod(0o600)
    envfile.warn_if_env_file_shared(env)
    assert capsys.readouterr().err == ""


# --- the Nemesis login for Traefik ---


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
@pytest.mark.parametrize(
    ("password", "salt"),
    [("pw", "saltsalt"), ("correct horse", "9efa0ad6"), ("", "abc"), ("x" * 40, "12345678"), ("pässwörd", "zzzzzzzz")],
)
def test_apr1_matches_openssl(password, salt):
    expected = subprocess.run(
        ["openssl", "passwd", "-apr1", "-salt", salt, "-stdin"], input=password + "\n", capture_output=True, text=True
    ).stdout.strip()
    assert envfile.apr1(password, salt) == expected


def test_login_defaults_user_and_is_stable(tmp_path):
    env = tmp_path / ".env"
    env.write_text('NEMESIS_PASSWORD="s3cret"\n')
    login = envfile.nemesis_login_htpasswd(env, {})
    assert login.startswith("n:$apr1$") and login == envfile.nemesis_login_htpasswd(env, {})
    other = envfile.nemesis_login_htpasswd(env, {"NEMESIS_PASSWORD": "different", "NEMESIS_USER": "bob"})
    assert other.startswith("bob:$apr1$") and other.split("$")[2] != login.split("$")[2]  # salt follows the password


@pytest.mark.parametrize(
    ("content", "message"),
    [("", "NEMESIS_PASSWORD is not set"), ('NEMESIS_USER="a:b"\nNEMESIS_PASSWORD="p"\n', "can't contain")],
)
def test_login_errors(tmp_path, content, message):
    env = tmp_path / ".env"
    env.write_text(content)
    with pytest.raises(envfile.EnvFileError, match=message):
        envfile.nemesis_login_htpasswd(env, {})
