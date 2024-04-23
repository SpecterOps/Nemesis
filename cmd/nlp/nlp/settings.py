# Standard Libraries
from enum import StrEnum

# 3rd Party Libraries
from nemesiscommon.settings import FileProcessingService
from pydantic import Field, PositiveInt


class NLPSettings(FileProcessingService):  # type: ignore
    rabbitmq_connection_uri: str
    embedding_model: str
    text_chunk_size: PositiveInt = 500 # size of text chunks for indexing
    plaintext_size_limit: PositiveInt = 100000000
    normalize_embeddings: str = "False"
    elasticsearch_url: str
    elasticsearch_user: str
    elasticsearch_password: str
    elastic_index_name: str

config = NLPSettings()  # type: ignore
