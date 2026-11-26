"""click commands for deploying Nemesis; registered on the top-level CLI group in cli/main.py."""

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import click
from cli.ctl.compose import (
    Controller,
    CtlError,
    Deployment,
    ordered_profiles,
    resolve_phoenix_enabled,
)
from cli.ctl.config import (
    CONFIG_ENVVAR,
    ENVIRONMENTS,
    EXAMPLE_CONFIG,
    PROFILES,
    PROJECT_CONFIG_NAME,
    PROJECT_DIR_ENVVAR,
    ConfigError,
    DeployConfig,
    load_effective_config,
    user_config_path,
)

_PROFILE_HELP = {
    "monitoring": "the monitoring profile (Grafana, Prometheus)",
    "jupyter": "the Jupyter profile",
    "llm": "the LLM services profile",
}

_EPILOG = (
    f"Defaults for the environment, profiles and --build come from {PROJECT_CONFIG_NAME} "
    "(see `config init`); flags override it."
)


@dataclass
class Resolved:
    cfg: DeployConfig
    project_dir: Path
    environment: str
    profiles: frozenset[str]


def _location_options(f: Callable) -> Callable:
    f = click.option(
        "--project-dir",
        type=click.Path(file_okay=False, path_type=Path),
        envvar=PROJECT_DIR_ENVVAR,
        show_envvar=True,
        help="Nemesis checkout to manage (default: the current directory or a parent).",
    )(f)
    f = click.option(
        "--config",
        "config_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        envvar=CONFIG_ENVVAR,
        show_envvar=True,
        help=f"{PROJECT_CONFIG_NAME} to use instead of the project or user config.",
    )(f)
    return f


def _deploy_options(f: Callable) -> Callable:
    """ENVIRONMENT argument, profile switches, --dry-run, and the location options."""
    f = click.option("--dry-run", is_flag=True, help="Print the docker commands without running them.")(f)
    for profile in reversed(PROFILES):
        f = click.option(
            f"--{profile}/--no-{profile}", default=None, help=f"Enable or disable {_PROFILE_HELP[profile]}."
        )(f)
    f = _location_options(f)
    f = click.argument("environment", type=click.Choice(ENVIRONMENTS), required=False)(f)
    return f


def _resolve(
    config_path: Path | None, project_dir: Path | None, environment: str | None, profile_flags: dict[str, bool | None]
) -> Resolved:
    try:
        cfg, project = load_effective_config(config_path, project_dir)
    except ConfigError as e:
        raise click.ClickException(str(e)) from e
    environment = environment or cfg.environment
    if environment is None:
        raise click.UsageError(
            f"Missing ENVIRONMENT ({' or '.join(ENVIRONMENTS)}); pass it or set deploy.environment "
            f"in {PROJECT_CONFIG_NAME}."
        )
    profiles = set(cfg.profiles)
    for name, enabled in profile_flags.items():
        if enabled is True:
            profiles.add(name)
        elif enabled is False:
            profiles.discard(name)
    return Resolved(cfg, project, environment, frozenset(profiles))


def _describe(r: Resolved) -> None:
    source = r.cfg.source or "none"
    profiles = ", ".join(ordered_profiles(r.profiles)) or "none"
    click.echo(f"Project: {r.project_dir}  Config: {source}  Profiles: {profiles}", err=True)


def _run(r: Resolved, dry_run: bool, action: Callable[[Controller], object]) -> object:
    try:
        return action(Controller(r.project_dir, dry_run=dry_run))
    except CtlError as e:
        raise click.ClickException(str(e)) from e


def _deployment(r: Resolved, build: bool) -> Deployment:
    try:
        phoenix = resolve_phoenix_enabled(os.environ, r.cfg.phoenix_enabled) if "llm" in r.profiles else True
    except CtlError as e:
        raise click.ClickException(str(e)) from e
    return Deployment(r.environment, r.profiles, build, phoenix)


@click.command(epilog=_EPILOG)
@_deploy_options
@click.option(
    "--build/--no-build",
    default=None,
    help="Build images before starting (prod; dev always builds).",
)
def start(environment, monitoring, jupyter, llm, dry_run, config_path, project_dir, build):
    """Build (optional) and start the Nemesis services in the background."""
    r = _resolve(config_path, project_dir, environment, {"monitoring": monitoring, "jupyter": jupyter, "llm": llm})
    _describe(r)
    build = build if build is not None else bool(r.cfg.build)
    _run(r, dry_run, lambda c: c.start(_deployment(r, build)))


def _reject_build(ctx: click.Context, _param: click.Parameter, value: bool) -> bool:
    if value:
        raise click.UsageError(f"The --build flag cannot be used with the '{ctx.info_name}' command.")
    return value


_hidden_build = click.option("--build", is_flag=True, hidden=True, expose_value=False, callback=_reject_build)


@click.command(epilog=_EPILOG)
@_deploy_options
@_hidden_build
def stop(environment, monitoring, jupyter, llm, dry_run, config_path, project_dir):
    """Stop and remove the services (containers and networks). Use the same profiles as `start`."""
    r = _resolve(config_path, project_dir, environment, {"monitoring": monitoring, "jupyter": jupyter, "llm": llm})
    _describe(r)
    _run(r, dry_run, lambda c: c.stop(_deployment(r, False)))


@click.command(epilog=_EPILOG)
@_deploy_options
@_hidden_build
def clean(environment, monitoring, jupyter, llm, dry_run, config_path, project_dir):
    """Stop and remove the services AND delete their data volumes."""
    r = _resolve(config_path, project_dir, environment, {"monitoring": monitoring, "jupyter": jupyter, "llm": llm})
    _describe(r)
    _run(r, dry_run, lambda c: c.clean(_deployment(r, False)))


@click.command(epilog=_EPILOG)
@_deploy_options
def status(environment, monitoring, jupyter, llm, dry_run, config_path, project_dir):
    """Show the state of the services (docker compose ps)."""
    r = _resolve(config_path, project_dir, environment, {"monitoring": monitoring, "jupyter": jupyter, "llm": llm})
    rc = _run(r, dry_run, lambda c: c.compose(_deployment(r, False), ["ps"]))
    raise SystemExit(rc)


@click.command(epilog=_EPILOG)
@click.argument("services", nargs=-1)
@click.option("-e", "--environment", type=click.Choice(ENVIRONMENTS), help="Environment (default: from config).")
@click.option("-f", "--follow", is_flag=True, help="Follow the log output.")
@click.option("-n", "--tail", default=None, help="Number of lines to show from the end of the logs.")
@click.option("--dry-run", is_flag=True, help="Print the docker command without running it.")
@_location_options
def logs(services, environment, follow, tail, dry_run, config_path, project_dir):
    """Show service logs (docker compose logs), e.g. `logs -f web-api`."""
    r = _resolve(config_path, project_dir, environment, {})
    args = ["logs", *(["-f"] if follow else []), *(["--tail", tail] if tail else []), *services]
    rc = _run(r, dry_run, lambda c: c.compose(_deployment(r, False), args))
    raise SystemExit(rc)


@click.group("config")
def config_group():
    """Show or create the nemesis.toml used by start/stop/clean."""


@config_group.command("show")
@_location_options
def config_show(config_path, project_dir):
    """Show the settings start/stop/clean would use, and where they came from."""
    try:
        cfg, project = load_effective_config(config_path, project_dir)
    except ConfigError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"project_dir     = {project}")
    click.echo(f"config file     = {cfg.source or '(none found)'}")
    click.echo(f"environment     = {cfg.environment or '(not set: pass dev or prod)'}")
    click.echo(f"profiles        = {', '.join(cfg.profiles) or '(none)'}")
    click.echo(f"build           = {bool(cfg.build)}")
    click.echo(f"phoenix_enabled = {'(default: true)' if cfg.phoenix_enabled is None else cfg.phoenix_enabled}")


@config_group.command("init")
@click.option("--user", "user_level", is_flag=True, help=f"Write {user_config_path()} instead of the project's file.")
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
@click.option("--project-dir", type=click.Path(file_okay=False, path_type=Path), envvar=PROJECT_DIR_ENVVAR)
def config_init(user_level, force, project_dir):
    """Write an example nemesis.toml to edit."""
    if user_level:
        target = user_config_path()
    else:
        try:
            _cfg, project = load_effective_config(None, project_dir)
        except ConfigError as e:
            raise click.ClickException(str(e)) from e
        target = project / PROJECT_CONFIG_NAME
    if target.exists() and not force:
        raise click.ClickException(f"{target} already exists (use --force to overwrite).")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(EXAMPLE_CONFIG)
    click.echo(f"Wrote {target}")


DEPLOY_COMMANDS: list[click.Command] = [start, stop, clean, status, logs, config_group]
