from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import ParseResult, urlparse

from cli.config import default_state_dir
from dynaconf import Dynaconf, Validator

DEFAULT_PENDING_GIVE_UP_DAYS = 7
DEFAULT_MAX_PENDING_SUBSCRIPTIONS = 10


def _lower_keys(data: dict) -> dict:
    """Lowercase keys recursively. Dynaconf keeps keys set by MYTHIC_SYNC_<SECTION>__<KEY> environment variables in
    upper case (e.g. ``CA_FILE``), while keys from the YAML file keep their own case."""
    return {str(k).lower(): _lower_keys(v) if isinstance(v, dict) else v for k, v in data.items()}


@dataclass
class UsernamePasswordCredential:
    username: str
    password: str


@dataclass
class TokenCredential:
    token: str


@dataclass
class MythicConfig:
    url: str
    credential: UsernamePasswordCredential | TokenCredential
    agent_id: str = "mythic"

    def __post_init__(self):
        if not isinstance(self.agent_id, str) or not self.agent_id.strip():
            raise ValueError("mythic.agent_id must be a nonempty string")

    @classmethod
    def from_dict(cls, data: dict) -> "MythicConfig":
        url_value = data["url"]
        if isinstance(url_value, list):
            url_value = url_value[0]

        cred_data = data["credential"]
        if "token" in cred_data:
            credential = TokenCredential(token=cred_data["token"])
        else:
            credential = UsernamePasswordCredential(username=cred_data["username"], password=cred_data["password"])

        return cls(url=url_value, credential=credential, agent_id=data.get("agent_id", "mythic"))


@dataclass
class NemesisConfig:
    url: ParseResult
    credential: UsernamePasswordCredential
    expiration_days: int
    max_file_size: int

    def __post_init__(self):
        # If a string was passed in, parse it
        if isinstance(self.url, str):
            self.url = urlparse(self.url)
        elif isinstance(self.url, list):
            self.url = urlparse(self.url[0])

        # Validate URL
        if not self.url.scheme or not self.url.netloc:
            raise ValueError(f"Invalid URL format - missing scheme or host: {self.url}")

    @classmethod
    def from_dict(cls, data: dict) -> "NemesisConfig":
        url_value = data["url"]
        if isinstance(url_value, list):
            url_value = url_value[0]

        return cls(
            url=url_value,
            credential=UsernamePasswordCredential(
                username=data["credential"]["username"],
                password=data["credential"]["password"],
            ),
            expiration_days=data["expiration_days"],
            max_file_size=data["max_file_size"],
        )


@dataclass
class DatabaseConfig:
    path: str

    @classmethod
    def from_dict(cls, data: dict) -> "DatabaseConfig":
        return cls(path=str(Path(str(data["path"])).expanduser()))


@dataclass
class NetworkingConfig:
    timeout_sec: int
    validate_https_certs: bool
    # PEM bundle of CAs to trust for Mythic instead of the system store; None uses the system store.
    ca_file: str | None = None

    def __post_init__(self):
        if self.ca_file is not None:
            if not isinstance(self.ca_file, str) or not self.ca_file.strip():
                raise ValueError("networking.ca_file must be a nonempty path")
            path = Path(self.ca_file).expanduser()
            if not path.is_file():
                raise ValueError(f"networking.ca_file not found: {path}")
            self.ca_file = str(path)

    @classmethod
    def from_dict(cls, data: dict) -> "NetworkingConfig":
        return cls(
            timeout_sec=data["timeout_sec"],
            validate_https_certs=data["validate_https_certs"],
            ca_file=data.get("ca_file"),
        )


@dataclass
class SyncConfig:
    # Give up on a download whose chunk count has not changed for this many days (dead callback).
    pending_give_up_days: int = DEFAULT_PENDING_GIVE_UP_DAYS
    # Live-query websockets for pending files (100 files each); pending files beyond these are polled.
    max_pending_subscriptions: int = DEFAULT_MAX_PENDING_SUBSCRIPTIONS

    def __post_init__(self):
        if isinstance(self.pending_give_up_days, bool) or not isinstance(self.pending_give_up_days, int):
            raise ValueError("sync.pending_give_up_days must be an integer")
        if self.pending_give_up_days <= 0:
            raise ValueError("sync.pending_give_up_days must be positive")
        if isinstance(self.max_pending_subscriptions, bool) or not isinstance(self.max_pending_subscriptions, int):
            raise ValueError("sync.max_pending_subscriptions must be an integer")
        if self.max_pending_subscriptions <= 0:
            raise ValueError("sync.max_pending_subscriptions must be positive")

    @classmethod
    def from_dict(cls, data: dict | None) -> "SyncConfig":
        data = data or {}
        return cls(
            pending_give_up_days=data.get("pending_give_up_days", DEFAULT_PENDING_GIVE_UP_DAYS),
            max_pending_subscriptions=data.get("max_pending_subscriptions", DEFAULT_MAX_PENDING_SUBSCRIPTIONS),
        )


@dataclass
class Settings:
    project: str
    mythic: MythicConfig
    nemesis: NemesisConfig
    db: DatabaseConfig
    networking: NetworkingConfig
    sync: SyncConfig = field(default_factory=SyncConfig)

    @classmethod
    def from_dynaconf(cls, dynaconf: Dynaconf) -> "Settings":
        sync = dynaconf.get("sync")
        return cls(
            project=dynaconf.project,
            mythic=MythicConfig.from_dict(_lower_keys(dynaconf.mythic.to_dict())),
            nemesis=NemesisConfig.from_dict(_lower_keys(dynaconf.nemesis.to_dict())),
            db=DatabaseConfig.from_dict(_lower_keys(dynaconf.db.to_dict())),
            networking=NetworkingConfig.from_dict(_lower_keys(dynaconf.networking.to_dict())),
            sync=SyncConfig.from_dict(_lower_keys(sync.to_dict()) if sync is not None else None),
        )


VALIDATORS = [
    # Mythic validators
    Validator("project", default="ASSESS-TEST", is_type_of=str),
    Validator("mythic.url", must_exist=True),
    Validator("mythic.credential", must_exist=True),
    Validator(
        "mythic.credential.username", must_exist=True, when=Validator("mythic.credential.token", must_exist=False)
    ),
    Validator(
        "mythic.credential.password", must_exist=True, when=Validator("mythic.credential.token", must_exist=False)
    ),
    Validator(
        "mythic.credential.username", must_exist=False, when=Validator("mythic.credential.token", must_exist=True)
    ),
    Validator(
        "mythic.credential.password", must_exist=False, when=Validator("mythic.credential.token", must_exist=True)
    ),
    Validator(
        "mythic.agent_id", default="mythic", is_type_of=str, condition=lambda v: isinstance(v, str) and bool(v.strip())
    ),
    # Nemesis validators
    Validator("nemesis.url", must_exist=True),
    Validator("nemesis.credential", must_exist=True),
    Validator("nemesis.credential.username", must_exist=True),
    Validator("nemesis.credential.password", must_exist=True),
    Validator("nemesis.expiration_days", default=100, is_type_of=int),
    Validator("nemesis.max_file_size", default=1_000_000_000, is_type_of=int),  # Default 1GB
    # Database validators
    # Per-user state directory, the same default as the Cobalt Strike and Outflank connectors.
    Validator("db.path", default=lambda _settings, _validator: str(default_state_dir())),
    # Networking validators
    Validator("networking.timeout_sec", default=30, is_type_of=int),
    Validator("networking.validate_https_certs", default=True, is_type_of=bool),
    # Sync validators
    Validator("sync.pending_give_up_days", default=DEFAULT_PENDING_GIVE_UP_DAYS, is_type_of=int, gt=0),
    Validator("sync.max_pending_subscriptions", default=DEFAULT_MAX_PENDING_SUBSCRIPTIONS, is_type_of=int, gt=0),
]


@lru_cache
def get_settings(config_file: str) -> Settings:
    dynaconf = Dynaconf(
        envvar_prefix="MYTHIC_SYNC",
        settings_files=[config_file],
        environments=False,
        load_dotenv=False,
        validators=VALIDATORS,
    )
    dynaconf.validators.validate()
    return Settings.from_dynaconf(dynaconf)
