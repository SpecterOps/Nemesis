# Standard Libraries
from typing import List

# 3rd Party Libraries
from attr import dataclass

QueueName = str
ExchangeName = str
ElasticIndex = str

NemesisExchange: ExchangeName = "nemesis"

NEMESIS_EXCHANGE: str = "nemesis"

NemesisQueue = str

#  Nemesis (Q)ueue Names (alphabetical order, no plurals)
Q_ALERT: NemesisQueue = "alert"
Q_AUTHENTICATION_DATA: NemesisQueue = "authentication_data"
Q_CHROMIUM_COOKIE_PROCESSED: NemesisQueue = "chromium_cookie_processed"
Q_CHROMIUM_COOKIE: NemesisQueue = "chromium_cookie"
Q_CHROMIUM_DOWNLOAD: NemesisQueue = "chromium_download"
Q_CHROMIUM_HISTORY: NemesisQueue = "chromium_history"
Q_CHROMIUM_LOGIN_PROCESSED: NemesisQueue = "chromium_login_processed"
Q_CHROMIUM_LOGIN: NemesisQueue = "chromium_login"
Q_CHROMIUM_STATE_FILE_PROCESSED: NemesisQueue = "chromium_state_file_processed"
Q_CHROMIUM_STATE_FILE: NemesisQueue = "chromium_state_file"
Q_COOKIE: NemesisQueue = "cookie"
Q_DPAPI_BLOB_PROCESSED: NemesisQueue = "dpapi_blob_processed"
Q_DPAPI_BLOB: NemesisQueue = "dpapi_blob"
Q_DPAPI_DOMAIN_BACKUPKEY: NemesisQueue = "dpapi_domain_backupkey"
Q_DPAPI_MASTERKEY_PROCESSED: NemesisQueue = "dpapi_masterkey_processed"
Q_DPAPI_MASTERKEY: NemesisQueue = "dpapi_masterkey"
Q_EXTRACTED_HASH: NemesisQueue = "extracted_hash"
Q_FILE_DATA_ENRICHED: NemesisQueue = "file_data_enriched"
Q_FILE_DATA_PLAINTEXT: NemesisQueue = "file_data_plaintext"
Q_FILE_DATA_SOURCECODE: NemesisQueue = "file_data_sourcecode"
Q_FILE_DATA: NemesisQueue = "file_data"
Q_FILE_INFORMATION: NemesisQueue = "file_information"
Q_NAMED_PIPE: NemesisQueue = "named_pipe"
Q_NETWORK_CONNECTION: NemesisQueue = "network_connection"
Q_PATH_LIST: NemesisQueue = "path_list"
Q_PROCESS_ENRICHED: NemesisQueue = "process_enriched"
Q_PROCESS: NemesisQueue = "process"
Q_RAW_DATA: NemesisQueue = "raw_data"
Q_REGISTRY_VALUE: NemesisQueue = "registry_value"
Q_SERVICE_ENRICHED: NemesisQueue = "service_enriched"
Q_SERVICE: NemesisQueue = "service"

ALL_QUEUES: List[NemesisQueue] = [
    Q_ALERT,
    Q_AUTHENTICATION_DATA,
    Q_CHROMIUM_COOKIE_PROCESSED,
    Q_CHROMIUM_COOKIE,
    Q_CHROMIUM_DOWNLOAD,
    Q_CHROMIUM_HISTORY,
    Q_CHROMIUM_LOGIN_PROCESSED,
    Q_CHROMIUM_LOGIN,
    Q_CHROMIUM_STATE_FILE_PROCESSED,
    Q_CHROMIUM_STATE_FILE,
    Q_COOKIE,
    Q_DPAPI_BLOB_PROCESSED,
    Q_DPAPI_BLOB,
    Q_DPAPI_DOMAIN_BACKUPKEY,
    Q_DPAPI_MASTERKEY_PROCESSED,
    Q_DPAPI_MASTERKEY,
    Q_EXTRACTED_HASH,
    Q_FILE_DATA_ENRICHED,
    Q_FILE_DATA_PLAINTEXT,
    Q_FILE_DATA_SOURCECODE,
    Q_FILE_DATA,
    Q_FILE_INFORMATION,
    Q_PATH_LIST,
    Q_PROCESS_ENRICHED,
    Q_PROCESS,
    Q_RAW_DATA,
    Q_REGISTRY_VALUE,
    Q_SERVICE_ENRICHED,
    Q_SERVICE,
    Q_NAMED_PIPE,
    Q_NETWORK_CONNECTION,
]


@dataclass
class QueueBinding:
    Exchange: str
    Queue: str
    RoutingKey: str


RABBITMQ_QUEUE_BINDINGS: dict[NemesisQueue, QueueBinding] = {}
for q in ALL_QUEUES:
    RABBITMQ_QUEUE_BINDINGS[q] = QueueBinding(NEMESIS_EXCHANGE, q, q)


ES_INDEX_AUTHENTICATION_DATA: ElasticIndex = "authentication_data"
ES_INDEX_EXTRACTED_HASH: ElasticIndex = "extracted_hash"
ES_INDEX_FILE_DATA_ENRICHED: ElasticIndex = "file_data_enriched"
ES_INDEX_FILE_DATA_PLAINTEXT: ElasticIndex = "file_data_plaintext"
ES_INDEX_FILE_DATA_SOURCECODE: ElasticIndex = "file_data_sourcecode"
ES_INDEX_FILE_INFORMATION: ElasticIndex = "file_information"
ES_INDEX_PROCESS_CATEGORY: ElasticIndex = "process_category"
ES_INDEX_REGISTRY_VALUE: ElasticIndex = "registry_value"
ES_INDEX_SERVICE_ENRICHED: ElasticIndex = "service_enriched"
ES_INDEX_NAMED_PIPE: ElasticIndex = "named_pipe"
ES_INDEX_NETWORK_CONNECTION: ElasticIndex = "network_connection"
ES_INDEX_TEXT_EMBEDDINGS: ElasticIndex = "text_embeddings"

ALL_ES_INDICIES: List[ElasticIndex] = [
    ES_INDEX_AUTHENTICATION_DATA,
    ES_INDEX_EXTRACTED_HASH,
    ES_INDEX_FILE_DATA_ENRICHED,
    ES_INDEX_FILE_DATA_PLAINTEXT,
    ES_INDEX_FILE_DATA_SOURCECODE,
    ES_INDEX_FILE_INFORMATION,
    ES_INDEX_PROCESS_CATEGORY,
    ES_INDEX_REGISTRY_VALUE,
    ES_INDEX_SERVICE_ENRICHED,
    ES_INDEX_NAMED_PIPE,
    ES_INDEX_NETWORK_CONNECTION,
    ES_INDEX_TEXT_EMBEDDINGS
]

NemesisEnrichment = str

#  Nemesis Enrichment Names
E_FILE_HASHES: NemesisEnrichment = "file_hashes"
E_KNOWN_FILE_PARSED: NemesisEnrichment = "known_file_parsed"
E_DPAPI_BLOB_SCAN: NemesisEnrichment = "dpapi_blob_scan"
E_DPAPI_BLOB_CARVED: NemesisEnrichment = "dpapi_blob_carved"
E_TEXT_EXTRACTED: NemesisEnrichment = "text_extracted"
E_PDF_CONVERSION: NemesisEnrichment = "pdf_conversion"
E_YARA_SCAN: NemesisEnrichment = "yara_scan"
E_NOSEYPARKER_SCAN: NemesisEnrichment = "noseyparker_scan"
E_ARCHIVE_CONTENTS_PROCESSED: NemesisEnrichment = "archive_contents_processed"
E_DOTNET_ANALYSIS: NemesisEnrichment = "dotnet_analysis"
E_UPDATE_CRACKLIST: NemesisEnrichment = "update_cracklist"
E_EXTRACT_PASSWORDS: NemesisEnrichment = "extract_passwords"
E_SUMMARIZE: NemesisEnrichment = "summarize"
E_NOSEYPARKER_SCAN_TEXT: NemesisEnrichment = "noseyparker_scan_text"  # NoseyParker scan, but on text
E_PROCESS_CATEGORY: NemesisEnrichment = "process_category"
E_SERVICE_CATEGORY: NemesisEnrichment = "service_category"
E_COOKIE_CLASSIFICATION: NemesisEnrichment = "cookie_classification"

NemesisEnrichmentTag = str

# file enrichment tags
E_TAG_CONTAINS_DPAPI: NemesisEnrichmentTag = "contains_dpapi"
E_TAG_NOSEYPARKER_RESULTS: NemesisEnrichmentTag = "noseyparker_results"
E_TAG_PARSED_CREDS: NemesisEnrichmentTag = "parsed_creds"
E_TAG_ENCRYPTED: NemesisEnrichmentTag = "encrypted"
E_TAG_DESERIALIZATION: NemesisEnrichmentTag = "deserialization"
E_TAG_CMD_EXECUTION: NemesisEnrichmentTag = "cmd_execution"
E_TAG_REMOTING: NemesisEnrichmentTag = "remoting"
E_TAG_YARA_MATCHES: NemesisEnrichmentTag = "yara_matches"
E_TAG_FILE_CANARY: NemesisEnrichmentTag = "file_canary"


# Yara rules to exclude from alerting/tagging due to false positives
#   matches are still preserved in the base file_data_enriched object
EXCLUDED_YARA_RULES = [
    "ConventionEngine_Keyword_Driver",
    "ConventionEngine_Keyword_Client",
    "ConventionEngine_Keyword_Hook"
]


NemesisRegistryTag = str

# registry filtering tags
REG_TAG_KEY: NemesisRegistryTag = "key_path_match"
REG_TAG_VALUE: NemesisRegistryTag = "value_match"
REG_TAG_DPAPI: NemesisRegistryTag = "dpapi_value"
