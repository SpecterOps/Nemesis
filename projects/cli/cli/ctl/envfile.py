"""Read .env values and generate deployment secrets in it.

A port of tools/lib/env_secrets.sh with the same parsing rules and file edits, so a .env written by one
tool is read identically by the other. Secret values are never printed.
"""

import hashlib
import re
import secrets
import stat
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from urllib.parse import quote

# Whitespace as matched by the POSIX [[:space:]] class (str.strip() would also strip Unicode spaces)
_SPACE = " \t\n\r\v\f"

_QUOTED_WITH_COMMENT = (
    re.compile(r'"([^"]*)"[ \t\n\r\v\f]*(#.*)?'),
    re.compile(r"'([^']*)'[ \t\n\r\v\f]*(#.*)?"),
)
_QUOTED_GREEDY = (re.compile(r'"(.*)"', re.DOTALL), re.compile(r"'(.*)'", re.DOTALL))
_LEADING_COMMENT = re.compile(r"[ \t\n\r\v\f]+#")
_INLINE_COMMENT = re.compile(r"[ \t\n\r\v\f]#")


class EnvFileError(Exception):
    """A .env value can't be used, or a secret could not be written."""


def _warn(message: str) -> None:
    print(message, file=sys.stderr)


def _read_lines(env_file: Path) -> list[str]:
    # Split on "\n" only, like grep/awk (str.splitlines() also splits on \v, \f, \x1c, ...)
    text = env_file.read_text(encoding="utf-8", errors="surrogateescape")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _line_pattern(name: str) -> re.Pattern[str]:
    return re.compile(rf"[ \t\n\r\v\f]*{re.escape(name)}=")


def parse_env_value(raw: str) -> str:
    """Unquote the text after NAME= on a .env line, following docker compose's comment rules.

    In an unquoted value, " #" (whitespace then #) starts an inline comment, while a "#" with no
    whitespace before it is part of the value; a quoted value keeps every "#" inside the quotes, and a
    comment may follow the closing quote.
    """
    value = raw.strip(_SPACE)
    for pattern in _QUOTED_WITH_COMMENT:
        if match := pattern.fullmatch(value):
            return match.group(1)
    for pattern in _QUOTED_GREEDY:
        # Quotes inside a quoted value: keep everything between the outer quotes
        if match := pattern.fullmatch(value):
            return match.group(1)
    if _LEADING_COMMENT.match(raw):
        # NAME= # comment -> empty
        return ""
    if match := _INLINE_COMMENT.search(value):
        value = value[: match.start()]
    return value.rstrip(_SPACE)


def env_file_value(env_file: Path, name: str) -> str:
    """The (unquoted) value of NAME in ENV_FILE; the last assignment wins. Empty when unset."""
    if not env_file.is_file():
        return ""
    pattern = _line_pattern(name)
    raw = None
    for line in _read_lines(env_file):
        if pattern.match(line):
            raw = line.split("=", 1)[1]
    return "" if raw is None else parse_env_value(raw)


def current_value(env_file: Path, name: str, environ: Mapping[str, str]) -> str:
    """NAME's value as docker compose sees it: the shell environment wins over .env."""
    return environ.get(name) or env_file_value(env_file, name)


def restrict_env_file_permissions(env_file: Path) -> None:
    """Restrict ENV_FILE (which holds every deployment secret) to its owner; a failure is only reported."""
    try:
        env_file.chmod(0o600)
    except OSError:
        _warn(f"Warning: could not restrict permissions on {env_file}; run: chmod 600 {env_file}")


def warn_if_env_file_shared(env_file: Path) -> None:
    """Warn (without changing anything) when ENV_FILE is readable or writable by group/others."""
    try:
        mode = stat.S_IMODE(env_file.stat().st_mode)
    except OSError:
        return
    if mode & 0o077:
        _warn(
            f"Warning: {env_file} (mode {mode:o}) is accessible to other users and holds secrets; "
            f"consider: chmod 600 {env_file}"
        )


def set_env_file_value(env_file: Path, name: str, value: str) -> None:
    """Set NAME="VALUE" in ENV_FILE, rewriting existing lines or appending one, then chmod it 0600."""
    lines = _read_lines(env_file)
    pattern = _line_pattern(name)
    new_line = f'{name}="{value}"'
    if any(pattern.match(line) for line in lines):
        content = "".join((new_line if pattern.match(line) else line) + "\n" for line in lines)
        # Rewrite in place (keeps the file's owner and inode)
        with env_file.open("w", encoding="utf-8", errors="surrogateescape", newline="") as f:
            f.write(content)
    else:
        with env_file.open("a", encoding="utf-8", errors="surrogateescape", newline="") as f:
            f.write(f"\n{new_line}\n")
    restrict_env_file_permissions(env_file)


def random_secret() -> str:
    return secrets.token_hex(24)


def ensure_random_env_secret(
    env_file: Path, name: str, environ: Mapping[str, str], public_defaults: Iterable[str] = ()
) -> None:
    """Generate a random NAME in ENV_FILE only when it has no value there (or in the environment).

    A value the operator set is always used as-is; if it is one of the public defaults, warn and keep it.
    """
    if not env_file.is_file():
        return
    current = current_value(env_file, name, environ)
    if current:
        if current in public_defaults:
            _warn(f"Warning: {name} is set to the public default value; change it to a random value.")
        return
    set_env_file_value(env_file, name, random_secret())
    print(f"Generated a random {name} in .env.")


def ensure_litellm_salt_key(env_file: Path, existing_data: bool, environ: Mapping[str, str]) -> None:
    """Settle LITELLM_SALT_KEY, which encrypts provider credentials stored in LiteLLM's database.

    It used to equal the master key (by default the public "sk-admin123"), and changing it would make
    those credentials unreadable, so an existing deployment keeps the old salt; a fresh one gets a
    random salt.
    """
    if not env_file.is_file():
        return
    if current_value(env_file, "LITELLM_SALT_KEY", environ):
        return
    if existing_data:
        # The salt used to be "sk-${LITELLM_ADMIN_PASSWORD:-admin123}"
        old_password = current_value(env_file, "LITELLM_ADMIN_PASSWORD", environ)
        set_env_file_value(env_file, "LITELLM_SALT_KEY", f"sk-{old_password or 'admin123'}")
        print("Kept the previous LITELLM_SALT_KEY in .env so existing LiteLLM credentials stay readable.")
        return
    set_env_file_value(env_file, "LITELLM_SALT_KEY", f"sk-{random_secret()}")
    print("Generated a random LITELLM_SALT_KEY in .env.")


def url_encode(value: str) -> str:
    """Percent-encode a value for the user or password part of a URL (UTF-8 bytes, uppercase hex)."""
    return quote(value, safe="", encoding="utf-8", errors="surrogateescape")


def url_encoded_credentials(env_file: Path, names: Iterable[str], environ: Mapping[str, str]) -> dict[str, str]:
    """NAME_URLENC variables for compose.yaml's connection URLs (postgresql://user:pass@host, amqp://...).

    compose.yaml builds them from ${NAME_URLENC:-${NAME}}, so passwords with @ : / # % or spaces work
    (issue #81). A "$" is refused: compose expands it inside .env values, so the encoded copy would no
    longer match what compose passes to Postgres/RabbitMQ.
    """
    encoded: dict[str, str] = {}
    bad: list[str] = []
    for name in names:
        value = current_value(env_file, name, environ)
        if not value:
            continue
        if "$" in value:
            bad.append(name)
            continue
        encoded[f"{name}_URLENC"] = url_encode(value)
    if bad:
        raise EnvFileError(
            f"{' '.join(bad)} contain(s) '$', which docker compose expands inside .env values. Use a value without '$'."
        )
    return encoded


_APR1_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def apr1(password: str, salt: str) -> str:
    """Apache's MD5-based htpasswd hash ($apr1$), as `openssl passwd -apr1 -salt SALT` computes it."""
    pw, salt_b, magic = password.encode(), salt.encode()[:8], b"$apr1$"
    ctx = hashlib.md5(pw + magic + salt_b)
    alternate = hashlib.md5(pw + salt_b + pw).digest()
    for remaining in range(len(pw), 0, -16):
        ctx.update(alternate[: min(16, remaining)])
    bits = len(pw)
    while bits:
        ctx.update(b"\0" if bits & 1 else pw[:1])
        bits >>= 1
    digest = ctx.digest()
    for i in range(1000):
        round_ = hashlib.md5(pw if i & 1 else digest)
        if i % 3:
            round_.update(salt_b)
        if i % 7:
            round_.update(pw)
        round_.update(digest if i & 1 else pw)
        digest = round_.digest()

    def to64(value: int, length: int) -> str:
        out = ""
        for _ in range(length):
            out += _APR1_ALPHABET[value & 0x3F]
            value >>= 6
        return out

    d = digest
    encoded = (
        to64((d[0] << 16) | (d[6] << 8) | d[12], 4)
        + to64((d[1] << 16) | (d[7] << 8) | d[13], 4)
        + to64((d[2] << 16) | (d[8] << 8) | d[14], 4)
        + to64((d[3] << 16) | (d[9] << 8) | d[15], 4)
        + to64((d[4] << 16) | (d[10] << 8) | d[5], 4)
        + to64(d[11], 2)
    )
    return f"$apr1${salt_b.decode()}${encoded}"


def nemesis_login_htpasswd(env_file: Path, environ: Mapping[str, str]) -> str:
    """NEMESIS_LOGIN_HTPASSWD for Traefik's basic auth: "<user>:<apr1 hash>" from NEMESIS_USER (default n) and
    NEMESIS_PASSWORD (environment first, then .env), like tools/lib/env_secrets.sh.

    apr1 rather than bcrypt: Traefik checks the hash on every request, and bcrypt costs ~50 ms of CPU each. The
    salt derives from the password, so the value is the same at every start and Traefik isn't recreated.
    """
    user = current_value(env_file, "NEMESIS_USER", environ) or "n"
    password = current_value(env_file, "NEMESIS_PASSWORD", environ)
    if not password:
        raise EnvFileError("NEMESIS_PASSWORD is not set; set it in .env")
    if ":" in user:
        raise EnvFileError("NEMESIS_USER can't contain ':'")
    salt = hashlib.sha256(f"nemesis-login:{password}".encode("utf-8", "surrogateescape")).hexdigest()[:8]
    return f"{user}:{apr1(password, salt)}"


def placeholders_for_compose_down(env_file: Path, names: Iterable[str], environ: Mapping[str, str]) -> dict[str, str]:
    """Throwaway values for required (${NAME:?}) secrets that were never generated.

    docker compose interpolates the whole file even for `down`/`ps`, and refuses to run when a required
    value is missing, so this lets a deployment that never started (or has no .env) be torn down.
    Nothing is written to ENV_FILE.
    """
    return {name: "unused-by-compose-down" for name in names if not current_value(env_file, name, environ)}
