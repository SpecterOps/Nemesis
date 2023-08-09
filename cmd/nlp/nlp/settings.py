# Standard Libraries
from enum import StrEnum

# 3rd Party Libraries
from nemesiscommon.settings import FileProcessingService
from pydantic import Field


class NLPSettings(FileProcessingService):  # type: ignore
    rabbitmq_connection_uri: str
    elastic_index_name: str
    embedding_model: str
    elastic_connection_uri: str
    elasticsearch_url: str


config = NLPSettings()  # type: ignore
