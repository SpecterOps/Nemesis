"""TLS certificate for Traefik (infra/traefik/certs/server.crt + server.key).

A port of tools/lib/tls_cert.sh (same checks, same certificate, same messages). No certificate ships with Nemesis:
one is created per deployment on start and renewed when it is a self-signed one about to expire. A certificate you
supplied is never replaced, only warned about when it is about to expire. Uses the openssl command, like the bash
script.
"""

import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from cli.ctl.envfile import current_value

SELF_SIGNED_ORG = "Nemesis self-signed"
RENEW_WITHIN_SECONDS = 30 * 24 * 3600


class CertError(Exception):
    """The certificate could not be created."""


def _openssl(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(["openssl", *args], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(["openssl", *args], 127, "", "openssl not found")


def certificate_fingerprint(cert_dir: Path) -> str:
    """NEMESIS_TLS_CERT_SHA256: Traefik reads the certificate only when it loads its configuration, so compose.yaml
    passes it this value to recreate Traefik whenever the certificate changes."""
    out = _openssl(["x509", "-in", str(cert_dir / "server.crt"), "-noout", "-fingerprint", "-sha256"]).stdout
    return out.strip().split("=", 1)[1] if "=" in out else ""


def nemesis_url_host(env_file: Path, environ: Mapping[str, str]) -> str:
    """Hostname or IP from NEMESIS_URL (environment first, then .env), or ""."""
    url = current_value(env_file, "NEMESIS_URL", environ)
    if "://" in url:
        url = url.split("://", 1)[1]
    url = url.split("/", 1)[0]
    url = url.rsplit("@", 1)[-1]
    if url.startswith("["):  # [IPv6]:port
        return url[1:].split("]", 1)[0]
    return url.split(":", 1)[0]


def ensure_tls_certificate(
    cert_dir: Path,
    env_file: Path,
    environ: Mapping[str, str],
    echo: Callable[[str], None] = print,
) -> None:
    """Make sure CERT_DIR holds a usable certificate (see the module docstring)."""
    crt, key = cert_dir / "server.crt", cert_dir / "server.key"
    if crt.is_file() and key.is_file():
        if _openssl(["x509", "-in", str(crt), "-noout", "-checkend", str(RENEW_WITHIN_SECONDS)]).returncode == 0:
            return
        elif SELF_SIGNED_ORG in _openssl(["x509", "-in", str(crt), "-noout", "-subject"]).stdout:
            echo("Renewing the self-signed TLS certificate (it expires within 30 days).")
        else:
            print(
                f"Warning: the TLS certificate {crt} expires within 30 days (or has expired); replace it.",
                file=sys.stderr,
            )
            return

    host = nemesis_url_host(env_file, environ)
    san = "DNS:localhost,IP:127.0.0.1"
    if host and host not in ("localhost", "127.0.0.1"):
        san += f",IP:{host}" if re.fullmatch(r"[0-9.]+", host) or ":" in host else f",DNS:{host}"
    cert_dir.mkdir(parents=True, exist_ok=True)
    new_key, new_crt = key.with_name(key.name + ".new"), crt.with_name(crt.name + ".new")
    made = _openssl(
        [
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-sha256",
            "-days", "365", "-subj", f"/O={SELF_SIGNED_ORG}/CN={host or 'localhost'}",
            "-addext", f"subjectAltName={san}", "-keyout", str(new_key), "-out", str(new_crt),
        ]
    )  # fmt: skip
    if made.returncode != 0:
        new_key.unlink(missing_ok=True)
        new_crt.unlink(missing_ok=True)
        raise CertError(f"could not create a TLS certificate in {cert_dir} (is openssl installed?)")
    os.chmod(new_key, 0o600)
    new_key.replace(key)
    new_crt.replace(crt)
    echo(
        f"Created a self-signed TLS certificate for {host or 'localhost'} in {cert_dir} "
        "(put your own server.crt/server.key there to use a different one)."
    )
