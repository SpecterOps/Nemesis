# Standard Libraries
import re
from enum import IntEnum
from typing import Any, List, Optional

# 3rd Party Libraries
from nemesiscommon.settings import FileProcessingService
from pydantic import Field, PositiveInt, validator
from pydantic.networks import AnyHttpUrl, AnyUrl, HttpUrl, Parts, PostgresDsn


class HttpUrlWithSlash(AnyHttpUrl):
    @classmethod
    def __get_validators__(cls):
        yield super().validate
        yield cls.validate

    @classmethod
    def validate_parts(cls, parts: "Parts", validate_port: bool = True) -> "Parts":
        path = parts.get("path")
        if not path or not path.endswith("/"):
            raise ValueError("URI must end with a '/'")

        return super().validate_parts(parts, validate_port=False)

    def __repr__(self):
        return f"HttpUrlWithSlash({super().__repr__()})"


class CrackWordlistSize(IntEnum):
    VALUE_10000 = 10000
    VALUE_100000 = 100000


class ElasticsearchSettings:
    user: str
    password: str
    url: str


class EnrichmentSettings(FileProcessingService):  # type: ignore
    rabbitmq_connection_uri: AnyUrl
    postgres_connection_uri: PostgresDsn
    tika_uri: HttpUrlWithSlash
    dotnet_uri: HttpUrlWithSlash
    gotenberg_uri: HttpUrlWithSlash
    ml_models_uri: HttpUrlWithSlash
    crack_list_uri: HttpUrlWithSlash
    model_word_limit: PositiveInt
    extracted_archive_size_limit: PositiveInt
    db_iteration_size: PositiveInt
    elasticsearch_user: str
    elasticsearch_password: str
    elasticsearch_url: HttpUrlWithSlash
    web_api_url: HttpUrlWithSlash
    public_kibana_url: HttpUrlWithSlash
    slack_webhook_url: Optional[str]
    slack_username: str
    slack_emoji: str
    slack_channel: Optional[str]
    tensorflow_uri: str
    context_words: PositiveInt
    chunk_size: PositiveInt
    ml_chunk_size: PositiveInt
    prob_threshold: float
    yara_api_port: int = Field(None, ge=0, le=65535)
    disable_alerting: bool = False
    crack_wordlist_top_words: CrackWordlistSize  # either 10000 or 100000 for now
    jtr_instances: PositiveInt = 1  # number of John the Ripper instances to run
    reprocessing_workers: PositiveInt = 5  # number of parallel reprocessing workers
    tasks: Optional[List[str]]  # List of tasks to start
    registry_value_batch_size: PositiveInt = 5000  # number of registry values to emit per reg carving message

    @validator("slack_channel")
    def slack_channel_is_valid(cls, channel: str) -> str:
        pattern = r"^#[a-zA-Z0-9_-]{1,80}$"

        if channel is None or channel == "":
            return None
        
        if re.match(pattern, channel):
            return channel
        else:
            raise ValueError("Slack channel must start with a '#' and be followed by 1-80 alphanumeric characters, hypens, or underscores")

    class Config:
        @classmethod
        def parse_env_var(cls, field_name: str, raw_val: str) -> Any:
            if field_name == "tasks":
                return [x for x in raw_val.split(",")]
            return raw_val


config = EnrichmentSettings()  # type: ignore
