"""Build and run the docker compose commands for start/stop/clean (and status/logs).

Mirrors tools/nemesis-ctl.sh step for step; tests/test_ctl_parity.py runs both against a stub `docker`
and checks they make the same calls and leave the same .env.
"""

import os
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cli.ctl import envfile, health
from cli.ctl.config import PROFILES

ACTIONS = ("start", "stop", "clean")

# Secrets the compose files require (${NAME:?}) that nemesis-ctl generates when unset
GENERATED_SECRETS = ("HASURA_ADMIN_SECRET", "LITELLM_SALT_KEY", "LITELLM_ADMIN_PASSWORD")
URL_CREDENTIALS = ("POSTGRES_USER", "POSTGRES_PASSWORD", "RABBITMQ_USER", "RABBITMQ_PASSWORD")
POSTGRES_VOLUME = "nemesis_postgres_data"
DEFAULT_WAIT_TIMEOUT = 600  # seconds
WAIT_POLL_INTERVAL = 2.0


class CtlError(Exception):
    """A pre-flight check failed; the message is shown to the operator."""


@dataclass(frozen=True)
class Deployment:
    environment: str  # "dev" | "prod"
    profiles: frozenset[str] = frozenset()
    build: bool = False
    phoenix_enabled: bool = True
    # start only: after `up -d`, wait until every service is healthy/running (or a one-shot exited 0)
    wait: bool = False
    wait_timeout: int = DEFAULT_WAIT_TIMEOUT

    @property
    def builds(self) -> bool:
        # Dev always builds, to catch local changes
        return self.environment == "dev" or self.build


# (argv, env, cwd, quiet) -> exit status; quiet discards the command's output
Runner = Callable[[Sequence[str], Mapping[str, str], Path, bool], int]


def subprocess_runner(argv: Sequence[str], env: Mapping[str, str], cwd: Path, quiet: bool) -> int:
    output = subprocess.DEVNULL if quiet else None
    try:
        return subprocess.run(list(argv), env=dict(env), cwd=cwd, check=False, stdout=output, stderr=output).returncode
    except FileNotFoundError as e:
        raise CtlError(f"{argv[0]} not found; is it installed and on PATH?") from e


# (argv, env, cwd) -> (exit status, stdout); stderr passes through
Capturer = Callable[[Sequence[str], Mapping[str, str], Path], tuple[int, str]]


def subprocess_capturer(argv: Sequence[str], env: Mapping[str, str], cwd: Path) -> tuple[int, str]:
    try:
        proc = subprocess.run(list(argv), env=dict(env), cwd=cwd, check=False, stdout=subprocess.PIPE, text=True)
    except FileNotFoundError as e:
        raise CtlError(f"{argv[0]} not found; is it installed and on PATH?") from e
    return proc.returncode, proc.stdout


def resolve_phoenix_enabled(environ: Mapping[str, str], configured: bool | None) -> bool:
    """$PHOENIX_ENABLED (as the bash script reads it) wins over nemesis.toml; the default is true."""
    value = environ.get("PHOENIX_ENABLED", "")
    if value:
        if value not in ("true", "false"):
            raise CtlError(f"PHOENIX_ENABLED must be 'true' or 'false', got '{value}'.")
        return value == "true"
    return True if configured is None else configured


def compose_base_args(d: Deployment, *, for_build: bool) -> tuple[dict[str, str], list[str]]:
    """Environment overrides and the `docker compose ...` prefix (profiles and files) for a deployment."""
    env: dict[str, str] = {}
    argv = ["docker", "compose"]
    # Same order as the bash script
    if "monitoring" in d.profiles:
        env["NEMESIS_MONITORING"] = "enabled"
        argv += ["--profile", "monitoring"]
    if "jupyter" in d.profiles:
        argv += ["--profile", "jupyter"]
    if "llm" in d.profiles:
        argv += ["--profile", "llm"]
        env["PHOENIX_ENABLED"] = "true" if d.phoenix_enabled else "false"
    if d.environment == "prod":
        argv += ["-f", "compose.yaml"]
        # The production build file is only needed for a build+start
        if for_build:
            argv += ["-f", "compose.prod.build.yaml"]
    return env, argv


def compose_command(action: str, d: Deployment) -> tuple[dict[str, str], list[str]]:
    """The main docker compose command for ACTION (start/stop/clean)."""
    env, argv = compose_base_args(d, for_build=action == "start" and d.environment == "prod" and d.build)
    if action == "start":
        argv += ["up", "--build", "-d"] if d.builds else ["up", "-d"]
    elif action == "stop":
        argv += ["down"]
    elif action == "clean":
        # --volumes removes the named volumes defined in the compose file
        argv += ["down", "--volumes"]
    else:
        raise ValueError(f"unknown action {action!r}")
    return env, argv


def format_command(env: Mapping[str, str], argv: Sequence[str]) -> str:
    """The command as `set -x` would show it."""
    prefix = ["env", *(f"{k}={v}" for k, v in env.items())] if env else []
    return "+ " + shlex.join([*prefix, *argv])


class Controller:
    """Runs one nemesis-ctl action against a checkout."""

    def __init__(
        self,
        project_dir: Path,
        *,
        environ: Mapping[str, str] | None = None,
        runner: Runner = subprocess_runner,
        dry_run: bool = False,
        echo: Callable[[str], None] | None = None,
        capturer: Capturer = subprocess_capturer,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.project_dir = project_dir
        self.env_file = project_dir / ".env"
        self.environ = dict(os.environ if environ is None else environ)
        self.runner = runner
        self.dry_run = dry_run
        self.echo = echo or (lambda message: print(message, flush=True))
        self.capturer = capturer
        self.clock = clock
        self.sleep = sleep

    # --- helpers ---

    def _run(self, argv: Sequence[str], extra_env: Mapping[str, str] | None = None, *, show: bool = True) -> int:
        extra_env = dict(extra_env or {})
        if show:
            print(format_command(extra_env, argv), file=sys.stderr, flush=True)
        if self.dry_run:
            return 0
        return self.runner(argv, {**self.environ, **extra_env}, self.project_dir, False)

    def _check(self, argv: Sequence[str], extra_env: Mapping[str, str] | None = None) -> None:
        if (rc := self._run(argv, extra_env)) != 0:
            raise SystemExit(rc)

    def _postgres_data_exists(self) -> bool:
        try:
            argv = ["docker", "volume", "inspect", POSTGRES_VOLUME]
            return self.runner(argv, self.environ, self.project_dir, True) == 0
        except CtlError:
            return False

    def _require_env_file(self) -> None:
        if not self.env_file.is_file():
            raise CtlError(
                f"Configuration file '.env' not found in {self.project_dir}\n"
                "Please create one by copying the example file:\n\n"
                "  cp env.example .env\n\n"
                "Then, review and customize the variables within it before running this command again."
            )

    def prepare_start_secrets(self) -> None:
        """Generate missing secrets in .env and export the URL-encoded credentials (start only)."""
        if self.dry_run:
            self.echo("(dry run: secrets in .env are not generated)")
            return
        envfile.ensure_random_env_secret(self.env_file, "HASURA_ADMIN_SECRET", self.environ, ["pass456"])
        # The salt must be settled before the admin password: it falls back to the old default only when
        # this deployment already has data that may have been encrypted with it.
        envfile.ensure_litellm_salt_key(self.env_file, self._postgres_data_exists(), self.environ)
        envfile.ensure_random_env_secret(self.env_file, "LITELLM_ADMIN_PASSWORD", self.environ, ["admin123"])
        envfile.warn_if_env_file_shared(self.env_file)
        try:
            self.environ.update(envfile.url_encoded_credentials(self.env_file, URL_CREDENTIALS, self.environ))
        except envfile.EnvFileError as e:
            raise CtlError(str(e)) from e

    def prepare_down_secrets(self) -> None:
        """stop/clean/status never generate or write secrets (a `clean` must not settle a salt for a volume
        it is about to delete), but compose still interpolates the file, so supply throwaway values."""
        self.environ.update(envfile.placeholders_for_compose_down(self.env_file, GENERATED_SECRETS, self.environ))

    def write_version_info(self) -> None:
        self.echo("Generating version information...")
        version = self.project_dir / "version.json"
        self._check([str(self.project_dir / "tools" / "generate-version.sh"), str(version), "local"])
        # Prod images bake it in at build time (dev mounts the repo-root copy)
        if not self.dry_run:
            shutil.copyfile(version, self.project_dir / "projects" / "frontend" / "public" / "version.json")

    # --- actions ---

    def start(self, d: Deployment) -> None:
        self._require_env_file()
        self.prepare_start_secrets()
        self.echo(f"--- Preparing to Start Services for '{d.environment}' environment ---")
        self.write_version_info()
        if d.builds:
            # Base images must be built for both dev and prod before starting
            self.echo("Ensuring base images are built...")
            self._check(["docker", "compose", "-f", "compose.base.yaml", "build"])
            self.echo("Building and starting services...")
        else:
            self.echo("Starting services...")
        self._execute("start", d)
        if d.wait:
            self.wait_until_ready(d)
            self._done("\nAll services are up and healthy.")
        else:
            self._done("\nServices are up and running.")

    def stop(self, d: Deployment) -> None:
        self.prepare_down_secrets()
        self.echo(f"--- Preparing to Stop Services for '{d.environment}' environment ---")
        self._execute("stop", d)
        self._done("\nServices and containers have been stopped and removed.")

    def clean(self, d: Deployment) -> None:
        self.prepare_down_secrets()
        self.echo(f"--- Preparing to Clean Services and Volumes for '{d.environment}' environment ---")
        self._execute("clean", d)
        self._done("\nServices, containers, and volumes have been stopped and removed.")

    def _done(self, message: str) -> None:
        self.echo("\n(dry run: nothing was run)" if self.dry_run else message)

    def _execute(self, action: str, d: Deployment) -> None:
        env, argv = compose_command(action, d)
        self.echo("\nRunning command:")
        self._check(argv, env)

    def wait_until_ready(self, d: Deployment) -> None:
        """Poll `docker compose ps` until every container is ready; raise CtlError on a failure or timeout."""
        env, base = compose_base_args(d, for_build=False)
        argv = [*base, "ps", "--all", "--format", "json"]
        self.echo(f"\nWaiting up to {d.wait_timeout}s for services to become healthy...")
        if self.dry_run:
            print(format_command(env, argv), file=sys.stderr, flush=True)
            return
        deadline = self.clock() + d.wait_timeout
        last = None
        while True:
            rc, out = self.capturer(argv, {**self.environ, **env}, self.project_dir)
            if rc != 0:
                raise CtlError(f"`docker compose ps` failed (exit {rc}) while waiting for services.")
            try:
                readiness = health.classify(health.parse_ps(out))
            except (ValueError, TypeError) as e:
                raise CtlError(f"Could not parse `docker compose ps` output: {e}") from e
            if readiness.failed:
                failed = ", ".join(f"{name} ({why})" for name, why in readiness.failed.items())
                raise CtlError(
                    f"Service(s) failed to start: {failed}\n"
                    f"Check their logs with: nemesis logs -e {d.environment} <service>"
                )
            if readiness.total and readiness.done:
                self.echo(health.summarize(readiness))
                return
            line = health.summarize(readiness) if readiness.total else "no containers yet"
            if line != last:
                self.echo(line)
                last = line
            if self.clock() >= deadline:
                raise CtlError(
                    f"Timed out after {d.wait_timeout}s; {line}\n"
                    "The services keep starting in the background; check them with `nemesis status` "
                    "and `nemesis logs`."
                )
            self.sleep(WAIT_POLL_INTERVAL)

    def compose(self, d: Deployment, args: Sequence[str]) -> int:
        """Run any other compose subcommand (ps, logs, ...) with the deployment's profiles and files."""
        self.prepare_down_secrets()
        env, argv = compose_base_args(d, for_build=False)
        return self._run([*argv, *args], env)


def ordered_profiles(profiles: frozenset[str]) -> list[str]:
    return [p for p in PROFILES if p in profiles]
