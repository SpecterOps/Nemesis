# Standard Libraries
from typing import AsyncGenerator

# 3rd Party Libraries
import enrichment.settings as settings
import google.protobuf.message
import httpx
import nemesiscommon.constants as constants
import nemesispb.nemesis_pb2 as pb
import structlog
from dependency_injector import containers, providers
from elasticsearch import AsyncElasticsearch
from enrichment.lib.nemesis_db import NemesisDb
from enrichment.services.text_extractor import TikaTextExtractor
from enrichment.settings import EnrichmentSettings
from enrichment.tasks.chromium_cookie import ChromiumCookie
from enrichment.tasks.data_expunge import DataExpunge
from enrichment.tasks.dpapi.dpapi import Dpapi
from enrichment.tasks.elastic_connector import ElasticConnector
from enrichment.tasks.file_processor import FileProcessor
from enrichment.tasks.postgres_connector.postgres_connector import (
    PostgresConnector, RegistryWatcher)
from enrichment.tasks.process_categorizer.categorizer import \
    CsvProcessCategorizer
from enrichment.tasks.process_categorizer.process_categorizer import \
    ProcessCategorizer
from enrichment.tasks.raw_data_tag.raw_data_tag import RawDataTag
from enrichment.tasks.registry_hive import RegistryHive
from enrichment.tasks.service_categorizer.categorizer import \
    TsvServiceCategorizer
from enrichment.tasks.service_categorizer.service_categorizer import \
    ServiceCategorizer
from enrichment.tasks.slack_webhook_alerter import SlackWebHookAlerter
from enrichment.tasks.webapi.crack_list.cracklist_api import CrackListApi
from enrichment.tasks.webapi.landingpage import LandingPageApi
from enrichment.tasks.webapi.ml_models_api import MlModelsApi
from enrichment.tasks.webapi.nemesis_api import NemesisApi
from enrichment.tasks.webapi.yara_api import YaraApi
from nemesiscommon.constants import NemesisQueue
from nemesiscommon.messaging_rabbitmq import (NemesisRabbitMQConsumer,
                                              NemesisRabbitMQProducer)
from nemesiscommon.services.alerter import NemesisAlerter
from nemesiscommon.storage_minio import StorageMinio
from nemesiscommon.storage_s3 import StorageS3

logger = structlog.get_logger(module=__name__)


async def create_consumer(
    rabbitmq_connection_uri: str,
    queue: NemesisQueue,
    message_type: google.protobuf.message.Message,
    service_id: str,
    num_events: int = 250,
):
    async with (await NemesisRabbitMQConsumer.create(rabbitmq_connection_uri, queue, message_type, service_id, num_events) as inputQ,):  # type: ignore
        yield inputQ


async def create_producer(rabbitmq_connection_uri: str, queue: NemesisQueue):
    async with (
        await NemesisRabbitMQProducer.create(
            rabbitmq_connection_uri,
            queue,
        ) as outputQ,
    ):
        yield outputQ


async def create_queue_map(rabbitmq_connection_uri: str):
    queues = {
        q: await NemesisRabbitMQProducer.create(
            rabbitmq_connection_uri,
            q,
        )
        for q in constants.ALL_QUEUES
    }
    yield queues

    # Shutdown
    for q in queues.values():
        await q.Close()


async def create_nemesis_db(postgres_connection_uri: str):
    db = await NemesisDb.create(postgres_connection_uri)
    yield db
    await db.Close()


async def create_http_retry_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    transport = httpx.AsyncHTTPTransport(retries=5)
    async with httpx.AsyncClient(transport=transport) as client:
        yield client


class Container(containers.DeclarativeContainer):
    #
    # Configuration
    #

    # Use this if you want to pass settings to the providers below
    config: EnrichmentSettings = providers.Configuration(pydantic_settings=[settings.config], strict=True)  # type: ignore

    # Use this if a class needs to be instantiated with a EnrichmentSettings object
    config2 = providers.Factory(EnrichmentSettings)

    #
    # Input Queues
    # Format: inputq_<queueName>_<taskWithNoUnderscores>
    #
    inputq_alert_slackwebhookalert = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_ALERT, pb.Alert, "slackwebhookalert"
    )
    inputq_filedata_fileprocessor = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_FILE_DATA, pb.FileDataIngestionMessage, "fileprocessor"
    )
    inputq_filedataenriched_fileprocessor = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_FILE_DATA_ENRICHED, pb.FileDataEnrichedMessage, "fileprocessor"
    )
    inputq_process_processcategorizer = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_PROCESS, pb.ProcessIngestionMessage, "processcategorizer"
    )
    inputq_service_servicecategorizer = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_SERVICE, pb.ServiceIngestionMessage, "servicecategorizer"
    )

    inputq_authdata_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_AUTHENTICATION_DATA,
        pb.AuthenticationDataIngestionMessage,
        "elasticconnector",
        num_events=500,
    )
    inputq_extractedhash_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_EXTRACTED_HASH,
        pb.ExtractedHashMessage,
        "elasticconnector",
        num_events=500,
    )
    inputq_processenriched_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_PROCESS_ENRICHED,
        pb.ProcessEnrichedMessage,
        "elasticconnector",
        num_events=500,
    )
    inputq_serviceenriched_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_SERVICE_ENRICHED,
        pb.ServiceEnrichedMessage,
        "elasticconnector",
        num_events=500,
    )
    inputq_fileinfo_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_FILE_INFORMATION,
        pb.FileInformationIngestionMessage,
        "elasticconnector",
        num_events=500,
    )
    inputq_filedataenriched_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_FILE_DATA_ENRICHED,
        pb.FileDataEnrichedMessage,
        "elasticconnector",
        num_events=500,
    )
    inputq_filedataplaintext_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_FILE_DATA_PLAINTEXT,
        pb.FileDataPlaintextMessage,
        "elasticconnector",
        num_events=500,
    )
    inputq_filedatasourcecode_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_FILE_DATA_SOURCECODE,
        pb.FileDataSourcecodeMessage,
        "elasticconnector",
        num_events=500,
    )
    inputq_registryvalue_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_REGISTRY_VALUE,
        pb.RegistryValueIngestionMessage,
        "elasticconnector",
        num_events=500,
    )
    inputq_namedpipe_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_NAMED_PIPE,
        pb.NamedPipeIngestionMessage,
        "elasticconnector",
        num_events=500,
    )
    inputq_networkconnection_elasticconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_NETWORK_CONNECTION,
        pb.NetworkConnectionIngestionMessage,
        "elasticconnector",
        num_events=500,
    )

    inputq_authdata_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_AUTHENTICATION_DATA,
        pb.AuthenticationDataIngestionMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_chromiumcookies_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_CHROMIUM_COOKIE,
        pb.ChromiumCookieMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_chromiumdownloads_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_CHROMIUM_DOWNLOAD,
        pb.ChromiumDownloadMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_chromiumhistory_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_CHROMIUM_HISTORY,
        pb.ChromiumHistoryMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_chromiumlogin_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_CHROMIUM_LOGIN,
        pb.ChromiumLoginMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_chromiumstatefile_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_CHROMIUM_STATE_FILE_PROCESSED,
        pb.ChromiumStateFileMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_dpapiblobprocessed_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_DPAPI_BLOB_PROCESSED,
        pb.DpapiBlobMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_extractedhash_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_EXTRACTED_HASH,
        pb.ExtractedHashMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_filedataenriched_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_FILE_DATA_ENRICHED,
        pb.FileDataEnrichedMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_fileinfo_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_FILE_INFORMATION,
        pb.FileInformationIngestionMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_pathlist_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_PATH_LIST,
        pb.PathListIngestionMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_rawdata_rawdatatagtask = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_RAW_DATA, pb.RawDataIngestionMessage, "rawdatatag", num_events=100
    )
    inputq_registryvalue_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_REGISTRY_VALUE,
        pb.RegistryValueIngestionMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_namedpipe_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_NAMED_PIPE,
        pb.NamedPipeIngestionMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_serviceenriched_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_SERVICE_ENRICHED,
        pb.ServiceEnrichedMessage,
        "postgresconnector",
        num_events=500,
    )
    inputq_networkconnection_postgresconnector = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_NETWORK_CONNECTION,
        pb.NetworkConnectionIngestionMessage,
        "postgresconnector",
        num_events=500,
    )

    inputq_dpapiblob_dpapitask = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_DPAPI_BLOB, pb.DpapiBlobMessage, "dpapi"
    )
    inputq_chromiumlogin_dpapitask = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_CHROMIUM_LOGIN, pb.ChromiumLoginMessage, "dpapi"
    )
    inputq_chromiumstatefile_dpapitask = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_CHROMIUM_STATE_FILE, pb.ChromiumStateFileMessage, "dpapi"
    )
    inputq_dpapidomainbackupkey_dpapitask = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_DPAPI_DOMAIN_BACKUPKEY, pb.DpapiDomainBackupkeyMessage, "dpapi"
    )
    inputq_dpapimasterkey_dpapitask = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_DPAPI_MASTERKEY, pb.DpapiMasterkeyMessage, "dpapi"
    )
    inputq_authenticationdata_dpapitask = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_AUTHENTICATION_DATA, pb.AuthenticationDataIngestionMessage, "dpapi"
    )

    inputq_cookie_chromiumcookie = providers.Resource(
        create_consumer, config.rabbitmq_connection_uri, constants.Q_COOKIE, pb.CookieIngestionMessage, "chromiumcookie", num_events=500
    )
    inputq_chromiumcookie_chromiumcookie = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_CHROMIUM_COOKIE,
        pb.ChromiumCookieMessage,
        "chromiumcookie",
        num_events=500,
    )

    inputq_filedataenriched_registryhive = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_FILE_DATA_ENRICHED,
        pb.FileDataEnrichedMessage,
        "registryhive",
    )

    #
    # Output Queues (alphabetical order)
    #

    outputq_alert = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_ALERT)
    outputq_authdata = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_AUTHENTICATION_DATA)
    outputq_chromiumcookies = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_CHROMIUM_COOKIE)
    outputq_chromiumcookiesprocessed = providers.Resource(
        create_producer, config.rabbitmq_connection_uri, constants.Q_CHROMIUM_COOKIE_PROCESSED
    )
    outputq_chromiumdownload = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_CHROMIUM_DOWNLOAD)
    outputq_chromiumhistory = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_CHROMIUM_HISTORY)
    outputq_chromiumlogin = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_CHROMIUM_LOGIN)
    outputq_chromiumloginprocessed = providers.Resource(
        create_producer, config.rabbitmq_connection_uri, constants.Q_CHROMIUM_LOGIN_PROCESSED
    )
    outputq_chromiumstatefile = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_CHROMIUM_STATE_FILE)
    outputq_chromiumstatefileprocessed = providers.Resource(
        create_producer, config.rabbitmq_connection_uri, constants.Q_CHROMIUM_STATE_FILE_PROCESSED
    )
    outputq_dpapiblob = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_DPAPI_BLOB)
    outputq_dpapiblobprocessed = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_DPAPI_BLOB_PROCESSED)
    outputq_dpapidomainbackupkey = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_DPAPI_DOMAIN_BACKUPKEY)
    outputq_dpapimasterkey = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_DPAPI_MASTERKEY)
    outputq_dpapimasterkeyprocessed = providers.Resource(
        create_producer, config.rabbitmq_connection_uri, constants.Q_DPAPI_MASTERKEY_PROCESSED
    )
    outputq_filedata = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_FILE_DATA)
    outputq_filedataenriched = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_FILE_DATA_ENRICHED)
    outputq_filedataplaintext = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_FILE_DATA_PLAINTEXT)
    outputq_filedatasourcecode = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_FILE_DATA_SOURCECODE)
    outputq_fileinfo = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_FILE_INFORMATION)
    outputq_namedpipe = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_NAMED_PIPE)
    outputq_networkconnection = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_NETWORK_CONNECTION)
    outputq_processenriched = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_PROCESS_ENRICHED)
    outputq_rawdata = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_RAW_DATA)
    outputq_registryvalue = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_REGISTRY_VALUE)
    outputq_service = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_SERVICE)
    outputq_serviceenriched = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_SERVICE_ENRICHED)
    queue_name_to_producer_map = providers.Resource(create_queue_map, config.rabbitmq_connection_uri)  # Required by the web_api service

    #
    # Services
    #
    alerter_service = providers.Factory(NemesisAlerter, outputq_alert, config.public_kibana_url)

    elasticsearch_client = providers.Factory(
        AsyncElasticsearch,
        config.elasticsearch_url,
        basic_auth=providers.List(config.elasticsearch_user, config.elasticsearch_password),
        verify_certs=False,
        retry_on_timeout=True,
        max_retries=10,
        request_timeout=10,
        maxsize=20,
    )

    http_client = providers.Resource(create_http_retry_client)

    storage_service_s3 = providers.Singleton(
        StorageS3,
        assessment_id=config.assessment_id,
        data_download_dir=config.data_download_dir,
        aws_access_key_id=config.aws_access_key_id,
        aws_secret_access_key=config.aws_secret_access_key,
        aws_default_region=config.aws_default_region,
        aws_bucket_name=config.aws_bucket,
        aws_kms_key_alias=config.aws_kms_key_alias,
    )
    storage_service_minio = providers.Singleton(
        StorageMinio,
        assessment_id=config.assessment_id,
        data_download_dir=config.data_download_dir,
        access_key=config.minio_root_user,
        secret_key=config.minio_root_password,
    )

    # this is overridden in bootstrap.py if s3 is specified,
    #   otherwise we use minio as the default
    storage_service = storage_service_minio

    text_extractor = providers.Factory(
        TikaTextExtractor,
        config.tika_uri,
        http_client,
    )

    database = providers.Resource(create_nemesis_db, config.postgres_connection_uri)

    process_categorizer = providers.Factory(CsvProcessCategorizer)
    service_categorizer = providers.Factory(TsvServiceCategorizer)
    registry_watcher = providers.Factory(RegistryWatcher, database, outputq_dpapiblob)

    #
    # Enrichment Service Tasks (alphabetical order)
    #
    task_alerting = providers.Factory(
        SlackWebHookAlerter,
        inputq_alert_slackwebhookalert,
        config.slack_webhook_url,
        config.slack_username,
        config.slack_emoji,
        config.slack_channel,
        http_client,
        config.disable_alerting,
    )

    task_chromiumcookie = providers.Factory(
        ChromiumCookie,
        database,
        inputq_chromiumcookie_chromiumcookie,
        inputq_cookie_chromiumcookie,
        outputq_chromiumcookies,
        outputq_chromiumcookiesprocessed,
    )

    task_dpapi = providers.Factory(
        Dpapi,
        config.data_download_dir,
        alerter_service,
        database,
        storage_service,
        inputq_chromiumlogin_dpapitask,
        inputq_chromiumstatefile_dpapitask,
        inputq_dpapiblob_dpapitask,
        inputq_dpapidomainbackupkey_dpapitask,
        inputq_dpapimasterkey_dpapitask,
        inputq_authenticationdata_dpapitask,
        outputq_chromiumloginprocessed,
        outputq_chromiumstatefileprocessed,
        outputq_dpapiblobprocessed,
        outputq_dpapimasterkeyprocessed,
    )

    task_elasticconnector = providers.Factory(
        ElasticConnector,
        storage_service,
        elasticsearch_client,
        config.web_api_url,
        config.public_kibana_url,
        inputq_authdata_elasticconnector,
        inputq_extractedhash_elasticconnector,
        inputq_filedataenriched_elasticconnector,
        inputq_filedataplaintext_elasticconnector,
        inputq_filedatasourcecode_elasticconnector,
        inputq_fileinfo_elasticconnector,
        inputq_processenriched_elasticconnector,
        inputq_registryvalue_elasticconnector,
        inputq_serviceenriched_elasticconnector,
        inputq_namedpipe_elasticconnector,
        inputq_networkconnection_elasticconnector,
    )

    task_fileprocessor = providers.Factory(
        FileProcessor,
        alerter_service,
        storage_service,
        database,
        text_extractor,
        # URIs
        config.crack_list_uri,
        config.dotnet_uri,
        config.gotenberg_uri,
        config.ml_models_uri,
        config.public_kibana_url,
        # Other settings
        config.chunk_size,
        config.data_download_dir,
        config.extracted_archive_size_limit,
        config.model_word_limit,
        # Queues
        inputq_filedata_fileprocessor,
        inputq_filedataenriched_fileprocessor,
        outputq_alert,
        outputq_authdata,
        outputq_chromiumcookies,
        outputq_chromiumdownload,
        outputq_chromiumhistory,
        outputq_chromiumlogin,
        outputq_chromiumstatefile,
        outputq_dpapiblob,
        outputq_dpapimasterkey,
        outputq_filedata,
        outputq_filedataenriched,
        outputq_filedataplaintext,
        outputq_filedatasourcecode,
        outputq_rawdata,
    )

    task_postgresconnector = providers.Factory(
        PostgresConnector,
        database,
        registry_watcher,
        inputq_authdata_postgresconnector,
        inputq_chromiumcookies_postgresconnector,
        inputq_chromiumdownloads_postgresconnector,
        inputq_chromiumhistory_postgresconnector,
        inputq_chromiumlogin_postgresconnector,
        inputq_chromiumstatefile_postgresconnector,
        inputq_dpapiblobprocessed_postgresconnector,
        inputq_extractedhash_postgresconnector,
        inputq_filedataenriched_postgresconnector,
        inputq_fileinfo_postgresconnector,
        inputq_pathlist_postgresconnector,
        inputq_registryvalue_postgresconnector,
        inputq_namedpipe_postgresconnector,
        inputq_serviceenriched_postgresconnector,
        inputq_networkconnection_postgresconnector,
    )

    task_processcategorizer = providers.Factory(
        ProcessCategorizer, inputq_process_processcategorizer, outputq_processenriched, process_categorizer
    )

    task_rawdatatag = providers.Factory(
        RawDataTag,
        storage_service,
        database,
        inputq_rawdata_rawdatatagtask,
        outputq_dpapidomainbackupkey,
        outputq_fileinfo,
        outputq_registryvalue,
        outputq_service,
        outputq_namedpipe,
        outputq_networkconnection,
    )

    task_registryhive = providers.Factory(
        RegistryHive,
        storage_service,
        config.registry_value_batch_size,
        inputq_filedataenriched_registryhive,
        outputq_registryvalue,
    )

    task_servicecategorizer = providers.Factory(
        ServiceCategorizer, inputq_service_servicecategorizer, outputq_serviceenriched, service_categorizer
    )

    task_dataexpunge = providers.Factory(
        DataExpunge,
        elasticsearch_client,
        database
    )

    #
    # Web APIs (alphabetical order)
    #
    task_cracklist_api = providers.Factory(CrackListApi, storage_service, config.log_level)
    task_mlmodels_api = providers.Factory(MlModelsApi, storage_service, config2)
    task_nemesis_api = providers.Factory(
        NemesisApi,
        storage_service,
        config.rabbitmq_connection_uri,
        alerter_service,
        database,
        elasticsearch_client,
        queue_name_to_producer_map,
        config.assessment_id,
        config.log_level,
        config.reprocessing_workers,
    )
    task_landingpage = providers.Factory(LandingPageApi, config.log_level)
    task_yara_api = providers.Factory(YaraApi, storage_service, config.yara_api_port, config.data_download_dir, config.log_level)

    tasks = providers.Aggregate(
        alerting=task_alerting,  # type: ignore
        chromiumcookie=task_chromiumcookie,  # type: ignore
        cracklist=task_cracklist_api,  # type: ignore
        dpapi=task_dpapi,  # type: ignore
        elasticconnector=task_elasticconnector,  # type: ignore
        fileprocessor=task_fileprocessor,  # type: ignore
        landingpage=task_landingpage,  # type: ignore
        mlmodels_api=task_mlmodels_api,  # type: ignore
        nemesis_api=task_nemesis_api,  # type: ignore
        postgresconnector=task_postgresconnector,  # type: ignore
        processcategorizer=task_processcategorizer,  # type: ignore
        rawdata=task_rawdatatag,  # type: ignore
        registryhive=task_registryhive,  # type: ignore
        servicecategorizer=task_servicecategorizer,  # type: ignore
        yara_api=task_yara_api,  # type: ignore
        dataexpunge=task_dataexpunge,  # type: ignore
    )
