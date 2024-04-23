from typing import AsyncGenerator

import asyncpg
import google.protobuf.message
import httpx
import nemesiscommon.constants as constants
import nemesispb.nemesis_pb2 as pb
from dependency_injector import containers, providers
from nemesiscommon.constants import NemesisQueue
from nemesiscommon.messaging_rabbitmq import (
    NemesisRabbitMQConsumer,
    NemesisRabbitMQProducer,
)
from nemesiscommon.services.alerter import NemesisAlerter
from nemesiscommon.tasking import TaskDispatcher

import passwordcracker.settings as settings
from passwordcracker.services.john_the_ripper_cracker import JohnTheRipperCracker
from passwordcracker.settings import PasswordCrackerSettings
from passwordcracker.tasks.password_cracker import PasswordCracker


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


async def create_nemesis_db_pool(postgres_connection_uri: str):
    pool = await asyncpg.create_pool(dsn=postgres_connection_uri)
    if not pool:
        raise Exception("Could not create database pool")
    yield pool
    await pool.Close()


async def create_http_retry_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    transport = httpx.AsyncHTTPTransport(retries=5)
    async with httpx.AsyncClient(transport=transport) as client:
        yield client


class Container(containers.DeclarativeContainer):
    #
    # Configuration
    #
    # Workaround for Pydantic2: https://github.com/ets-labs/python-dependency-injector/issues/755#issuecomment-1885607691
    config = providers.Configuration()
    json_config = settings.config.model_dump(mode="json")
    config.from_dict(json_config)

    # Use this if a class needs to be instantiated with a PasswordCrackerSettings object
    config2 = providers.Factory(PasswordCrackerSettings)

    #
    # Queues
    #
    inputq_passwordcracker_passwordcrackertask = providers.Resource(
        create_consumer,
        config.rabbitmq_connection_uri,
        constants.Q_AUTHENTICATION_DATA,
        pb.AuthenticationDataIngestionMessage,
        "passwordcracker",
        num_events=1,
    )
    outputq_alert = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_ALERT)
    outputq_extractedhash = providers.Resource(create_producer, config.rabbitmq_connection_uri, constants.Q_EXTRACTED_HASH)

    #
    # Services
    #
    http_client = providers.Resource(create_http_retry_client)

    alerting_service = providers.Factory(
        NemesisAlerter,
        outputq_alert,
        config.public_nemesis_url,
    )
    cracker_service = providers.Factory(
        JohnTheRipperCracker,
        config.data_download_dir,
    )

    database_pool = providers.Resource(create_nemesis_db_pool, config.postgres_connection_uri)

    #
    # passwordcracker Service Tasks
    #
    task_passwordcracker = providers.Factory(
        PasswordCracker,
        config2,
        alerting_service,
        database_pool,
        cracker_service,
        inputq_passwordcracker_passwordcrackertask,
        outputq_extractedhash,
    )

    task_list = providers.List(
        task_passwordcracker,
    )

    task_dispatcher = providers.Factory(TaskDispatcher, task_list, config.prometheus_port)
