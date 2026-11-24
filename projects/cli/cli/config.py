import os
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import yaml
from cli.tls_trust import resolve_ca_file
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator


class BaseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")


# Optional PEM file of CAs to trust for a server instead of the system trust store; validated on load.
CaFile = Annotated[
    str | None,
    AfterValidator(resolve_ca_file),
    Field(description="Optional PEM file of CAs to trust for this server instead of the system trust store"),
]


class StrictHttpUrl(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v: str, info) -> "StrictHttpUrl":
        if not isinstance(v, str):
            raise ValueError("URL must be a string")

        # Parse the URL
        parsed = urlparse(v)

        # Check for query/fragment
        if parsed.query or parsed.fragment:
            raise ValueError("URL cannot contain query parameters or fragments")

        # Ensure it's http/https
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use HTTP or HTTPS protocol")

        # Ensure there's a netloc (domain)
        if not parsed.netloc:
            raise ValueError("URL must contain a valid domain")

        # Store without trailing slash
        return cls(v.rstrip("/"))

    def __str__(self) -> str:
        return self.rstrip("/")

    def __repr__(self) -> str:
        return f"StrictHttpUrl('{self.rstrip('/')}')"


class PasswordCredential(BaseConfig):
    username: str
    password: str


class TokenCredential(BaseConfig):
    token: str


class NemesisConfig(BaseConfig):
    url: StrictHttpUrl
    credential: PasswordCredential
    expiration_days: Annotated[int, Field(gt=0, description="Days until uploaded files are deleted")] = 100
    max_file_size: Annotated[int, Field(gt=0, description="Maximum file size in bytes")] = 1_000_000_000
    ca_file: CaFile = None


class MythicConfig(BaseConfig):
    url: StrictHttpUrl
    credential: PasswordCredential | TokenCredential
    agent_id: str = Field(
        default="mythic", min_length=1, pattern=r"\S", description="Agent identifier for uploaded Mythic files"
    )

    @field_validator("credential")
    @classmethod
    def validate_credential(cls, v):
        if isinstance(v, dict):
            if "token" in v:
                return TokenCredential(**v)
            return PasswordCredential(**v)
        return v


class OutflankConfig(BaseConfig):
    url: StrictHttpUrl
    credential: PasswordCredential
    agent_id: str = Field(
        default="stage1", min_length=1, pattern=r"\S", description="Agent identifier for uploaded Outflank files"
    )
    downloads_dir_path: Path | None = Field(
        None,
        description="Optional: Path to Outflank C2's upload directory where files will be pulled from instead of the Outflank API",
    )
    poll_interval_sec: Annotated[int, Field(gt=0, description="Polling interval of the Outflank API in seconds")] = 3
    ca_file: CaFile = None

    @field_validator("downloads_dir_path")
    @classmethod
    def validate_path(cls, v):
        if v is None:
            return None
        return Path(v)


class CobaltStrikeConfig(BaseConfig):
    url: StrictHttpUrl
    credential: PasswordCredential
    agent_id: str = Field(
        default="cobaltstrike",
        min_length=1,
        pattern=r"\S",
        description="Agent identifier for uploaded Cobalt Strike files",
    )
    project: str = Field(description="Project name for Nemesis file uploads")
    poll_interval_sec: Annotated[
        int, Field(gt=0, description="Polling interval of the Cobalt Strike API in seconds")
    ] = 3
    ca_file: CaFile = None


def default_state_dir() -> Path:
    """Per-user connector state directory: $XDG_STATE_HOME/nemesis/connectors or ~/.local/state/nemesis/connectors.

    A per-user default avoids a shared, predictable /tmp path that another local user could pre-create to read,
    poison or block connector state.
    """
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "nemesis" / "connectors"


class Config(BaseConfig):
    cache_db_path: Path = Field(default_factory=default_state_dir, description="LevelDB cache path")
    conn_timeout_sec: Annotated[int, Field(gt=0, description="Connection timeout in seconds")] = 30
    validate_https_certs: bool = Field(True, description="Whether to validate HTTPS certificates")

    nemesis: NemesisConfig
    mythic: list[MythicConfig] | None = Field(default_factory=list)
    outflank: list[OutflankConfig] | None = Field(default_factory=list)
    cobaltstrike: list[CobaltStrikeConfig] | None = Field(default_factory=list)

    @field_validator("mythic", "outflank", "cobaltstrike", mode="before")
    @classmethod
    def ensure_list(cls, v):
        if v is None:
            return []
        elif isinstance(v, dict):
            return [v]
        return v

    @field_validator("cache_db_path", mode="before")
    @classmethod
    def validate_cache_path(cls, v):
        return Path(v).expanduser()


def load_config(config_path: str) -> Config:
    """Load and validate configuration from YAML file"""
    with open(config_path) as f:
        config_dict = yaml.safe_load(f)
    return Config(**config_dict)
