# Standard Libraries
import logging
import os
from enum import StrEnum
from typing import Any

# 3rd Party Libraries
import yaml
from pydantic import BaseSettings, Field, validator
from pydantic.env_settings import SettingsSourceCallable
from pydantic.networks import HttpUrl, Parts


class HttpUrlWithSlash(HttpUrl):
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
    prometheus_port: int = Field(None, ge=0, le=65535)
    assessment_id: str

    @validator("log_level")
    def method_is_valid(cls, level: str) -> str:
        levelName = logging.getLevelName(level)

        if isinstance(levelName, int):
            return level
        else:
            raise ValueError(f"must be valid log level from Python's 'logging' module, got '{level}'")

    # Load settings from a YAML file and from environment variables
    class Config:
        @classmethod
        def customise_sources(
            cls,
            init_settings: SettingsSourceCallable,
            env_settings: SettingsSourceCallable,
            file_secret_settings: SettingsSourceCallable,
        ) -> tuple[SettingsSourceCallable, ...]:
            def yml_config_setting(settings: BaseSettings) -> dict[str, Any]:
                if not os.path.exists("config.yml"):
                    return {}
                try:
                    with open("config.yml") as f:
                        conf = yaml.safe_load(f)
                        if not conf:
                            conf = {}

                        return conf
                except:
                    # Do nothing since env vars might be specified
                    return {}

            # Add load from yml file, change priority and remove file secret option
            return env_settings, yml_config_setting


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
