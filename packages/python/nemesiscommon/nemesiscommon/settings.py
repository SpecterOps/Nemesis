# Standard Libraries
import logging
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, AnyHttpUrl, Field, field_validator

# 3rd Party Libraries
from pydantic_core import Url
from pydantic_settings import BaseSettings


def check_url_has_slash(v: Url) -> Url:
    if not v or not v.path or not v.path.endswith("/"):
        raise ValueError("URL must end with a '/'")
    return v

HttpUrlWithSlash = Annotated[AnyHttpUrl, AfterValidator(check_url_has_slash)]


class EnvironmentSettings(StrEnum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    TEST = "test"

    def is_development(self):
        return self.value == EnvironmentSettings.DEVELOPMENT.value

    def is_production(self):
        return self.value == EnvironmentSettings.PRODUCTION.value

    def is_test(self):
        return self.value == EnvironmentSettings.TEST.value


class NemesisServiceSettings(BaseSettings):
    environment: EnvironmentSettings
    log_level: str
    log_color_enabled: bool = Field(True)
    prometheus_port: int = Field(None, ge=0, le=65535)
    assessment_id: str

    @field_validator("log_level")
    def method_is_valid(cls, level: str) -> str:
        levelName = logging.getLevelName(level)

        if isinstance(levelName, int):
            return level
        else:
            raise ValueError(f"must be valid log level from Python's 'logging' module, got '{level}'")


class FileProcessingService(NemesisServiceSettings):
    aws_bucket: str
    aws_default_region: str
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_kms_key_alias: str
    data_download_dir: str
    storage_provider: str
    minio_root_user: str
    minio_root_password: str
