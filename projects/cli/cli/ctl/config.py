"""nemesis.toml: defaults for `nemesis-ctl`, so start/stop/clean don't need the same flags every time.

Lookup order for the config file (the first one found is used, files are not merged):
  1. --config PATH, or $NEMESIS_CONFIG
  2. <project dir>/nemesis.toml
  3. $XDG_CONFIG_HOME/nemesis/nemesis.toml (default ~/.config/nemesis/nemesis.toml)

Command-line flags always win over the file.
"""

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ENVIRONMENTS = ("dev", "prod")
PROFILES = ("monitoring", "jupyter", "llm")

CONFIG_ENVVAR = "NEMESIS_CONFIG"
PROJECT_DIR_ENVVAR = "NEMESIS_PROJECT_DIR"
PROJECT_CONFIG_NAME = "nemesis.toml"
# A file only the repo root has (projects/cli has its own compose.yaml)
PROJECT_MARKER = "compose.base.yaml"

_DEPLOY_KEYS = {"environment", "build", "profiles", "phoenix_enabled", "project_dir", "wait", "wait_timeout"}


class ConfigError(Exception):
    """The config file is invalid, or the Nemesis checkout could not be found."""


@dataclass
class DeployConfig:
    """The [deploy] table. None means "not set": the command line or built-in default applies."""

    environment: str | None = None
    build: bool | None = None
    profiles: list[str] = field(default_factory=list)
    phoenix_enabled: bool | None = None
    wait: bool | None = None
    wait_timeout: int | None = None
    project_dir: Path | None = None
    source: Path | None = None  # file this was loaded from


def user_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "nemesis" / PROJECT_CONFIG_NAME


def _expect(value: object, kind: type, key: str, path: Path) -> None:
    if not isinstance(value, kind):
        raise ConfigError(f"{path}: deploy.{key} must be a {kind.__name__}, got {value!r}")


def load_config(path: Path) -> DeployConfig:
    """Parse and validate a nemesis.toml file."""
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except OSError as e:
        raise ConfigError(f"Cannot read config file {path}: {e.strerror}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: invalid TOML: {e}") from e

    deploy = data.get("deploy", {})
    if not isinstance(deploy, dict):
        raise ConfigError(f"{path}: [deploy] must be a table")
    if unknown := sorted(set(deploy) - _DEPLOY_KEYS):
        raise ConfigError(f"{path}: unknown key(s) in [deploy]: {', '.join(unknown)}")

    cfg = DeployConfig(source=path)
    if "environment" in deploy:
        _expect(deploy["environment"], str, "environment", path)
        if deploy["environment"] not in ENVIRONMENTS:
            raise ConfigError(f"{path}: deploy.environment must be one of {', '.join(ENVIRONMENTS)}")
        cfg.environment = deploy["environment"]
    if "build" in deploy:
        _expect(deploy["build"], bool, "build", path)
        cfg.build = deploy["build"]
    if "phoenix_enabled" in deploy:
        _expect(deploy["phoenix_enabled"], bool, "phoenix_enabled", path)
        cfg.phoenix_enabled = deploy["phoenix_enabled"]
    if "wait" in deploy:
        _expect(deploy["wait"], bool, "wait", path)
        cfg.wait = deploy["wait"]
    if "wait_timeout" in deploy:
        timeout = deploy["wait_timeout"]
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            raise ConfigError(f"{path}: deploy.wait_timeout must be a positive number of seconds, got {timeout!r}")
        cfg.wait_timeout = timeout
    if "profiles" in deploy:
        profiles = deploy["profiles"]
        if not isinstance(profiles, list) or not all(isinstance(p, str) for p in profiles):
            raise ConfigError(f"{path}: deploy.profiles must be a list of strings")
        if unknown := sorted(set(profiles) - set(PROFILES)):
            raise ConfigError(f"{path}: unknown profile(s) {', '.join(unknown)}; choose from {', '.join(PROFILES)}")
        cfg.profiles = profiles
    if "project_dir" in deploy:
        _expect(deploy["project_dir"], str, "project_dir", path)
        # Relative paths are relative to the config file
        cfg.project_dir = (path.parent / Path(deploy["project_dir"]).expanduser()).resolve()
    return cfg


def _find_upwards(start: Path) -> Path | None:
    for directory in (start, *start.parents):
        if (directory / PROJECT_MARKER).is_file():
            return directory
    return None


def is_project_dir(path: Path) -> bool:
    return (path / PROJECT_MARKER).is_file()


def resolve_project_dir(explicit: Path | None, cfg: DeployConfig | None, cwd: Path | None = None) -> Path:
    """Locate the Nemesis checkout: --project-dir/$NEMESIS_PROJECT_DIR, then the config's project_dir,
    then the current directory or a parent, then the checkout this package was installed from."""
    candidates: list[tuple[str, Path | None]] = [
        ("--project-dir", explicit),
        ("deploy.project_dir", cfg.project_dir if cfg else None),
    ]
    for label, path in candidates:
        if path is None:
            continue
        path = path.expanduser().resolve()
        if not is_project_dir(path):
            raise ConfigError(f"{label} {path} is not a Nemesis checkout (no {PROJECT_MARKER})")
        return path
    found = _find_upwards((cwd or Path.cwd()).resolve()) or _find_upwards(Path(__file__).resolve().parent)
    if found is None:
        raise ConfigError(
            "Could not find the Nemesis checkout. Run from inside it, or pass --project-dir "
            f"(or set ${PROJECT_DIR_ENVVAR})."
        )
    return found


def load_effective_config(
    config_path: Path | None, project_dir: Path | None, cwd: Path | None = None
) -> tuple[DeployConfig, Path]:
    """Find the config file and the project directory together (see the module docstring for the order)."""
    if config_path is not None:
        cfg = load_config(config_path)
        return cfg, resolve_project_dir(project_dir, cfg, cwd)

    user_path = user_config_path()
    user_cfg = load_config(user_path) if user_path.is_file() else None
    project = resolve_project_dir(project_dir, user_cfg, cwd)
    project_path = project / PROJECT_CONFIG_NAME
    if project_path.is_file():
        return load_config(project_path), project
    return user_cfg or DeployConfig(), project


EXAMPLE_CONFIG = """\
# nemesis.toml - defaults for `nemesis-ctl` (the Python version of tools/nemesis-ctl.sh).
# Flags on the command line always override these values.
# Secrets and service settings stay in .env; this file only controls how the deployment is run.

[deploy]
# Environment used when none is given on the command line: "prod" or "dev".
environment = "prod"

# Profiles to enable for start/stop/clean: "monitoring", "jupyter", "llm".
# Keeping them here means stop/clean always match what start used.
profiles = []

# prod only: build images locally instead of using the published ones (dev always builds).
build = false

# start: after the containers are up, wait until every service is healthy (or a one-shot init
# container has finished), and fail if one exits with an error or the timeout passes.
wait = false
# wait_timeout = 600   # seconds

# With the llm profile: enable Phoenix LLM tracing. $PHOENIX_ENABLED overrides this.
# phoenix_enabled = true

# Only useful in ~/.config/nemesis/nemesis.toml: the checkout to manage when not run from inside one.
# project_dir = "~/Nemesis"
"""
