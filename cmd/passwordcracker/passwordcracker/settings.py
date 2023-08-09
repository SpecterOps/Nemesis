# Standard Libraries
from enum import IntEnum

# 3rd Party Libraries
from nemesiscommon.settings import HttpUrlWithSlash, NemesisServiceSettings
from pydantic.networks import AnyUrl


class CrackWordlistSize(IntEnum):
    VALUE_10000 = 10000
    VALUE_100000 = 100000


class PasswordCrackerSettings(NemesisServiceSettings):  # type: ignore
    rabbitmq_connection_uri: AnyUrl
    public_kibana_url: HttpUrlWithSlash
    data_download_dir: str
    crack_wordlist_top_words: CrackWordlistSize  # either 10000 or 100000 for now


config = PasswordCrackerSettings()  # type: ignore
