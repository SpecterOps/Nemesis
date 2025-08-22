from dataclasses import dataclass
from functools import lru_cache
from typing import Union
from urllib.parse import ParseResult, urlparse

from dynaconf import Dynaconf, Validator


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
    credential: Union[UsernamePasswordCredential, TokenCredential]

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

        return cls(url=url_value, credential=credential)


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
        return cls(path=data["path"])


@dataclass
class NetworkingConfig:
    timeout_sec: int
    validate_https_certs: bool

    @classmethod
    def from_dict(cls, data: dict) -> "NetworkingConfig":
        return cls(
            timeout_sec=data["timeout_sec"],
            validate_https_certs=data["validate_https_certs"],
        )


@dataclass
class Settings:
    project: str
    mythic: MythicConfig
    nemesis: NemesisConfig
    db: DatabaseConfig
    networking: NetworkingConfig

    @classmethod
    def from_dynaconf(cls, dynaconf: Dynaconf) -> "Settings":
        return cls(
            project=dynaconf.project,
            mythic=MythicConfig.from_dict(dynaconf.mythic.to_dict()),
            nemesis=NemesisConfig.from_dict(dynaconf.nemesis.to_dict()),
            db=DatabaseConfig.from_dict(dynaconf.db.to_dict()),
            networking=NetworkingConfig.from_dict(dynaconf.networking.to_dict()),
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
        "mythic.credential.token", must_exist=True, when=Validator("mythic.credential.username", must_exist=False)
    ),
    # Nemesis validators
    Validator("nemesis.url", must_exist=True),
    Validator("nemesis.credential", must_exist=True),
    Validator("nemesis.credential.username", must_exist=True),
    Validator("nemesis.credential.password", must_exist=True),
    Validator("nemesis.expiration_days", default=100, is_type_of=int),
    Validator("nemesis.max_file_size", default=1_000_000_000, is_type_of=int),  # Default 1GB
    # Database validators
    Validator("db.path", default="mythic_sync.db"),
    # Networking validators
    Validator("networking.timeout_sec", default=30, is_type_of=int),
    Validator("networking.validate_https_certs", default=True, is_type_of=bool),
]


@lru_cache
def get_settings(config_file: str) -> Settings:
    dynaconf = Dynaconf(
        envvar_prefix="MYTHIC_SYNC",
        settings_files=[config_file],
        environments=False,
        load_dotenv=True,
        validators=VALIDATORS,
    )
    dynaconf.validators.validate()
    return Settings.from_dynaconf(dynaconf)
