# 3rd Party Libraries
import structlog
from aio_pika import ExchangeType, connect_robust

from nemesiscommon.messaging_rabbitmq import RABBITMQ_QUEUE_BINDINGS

logger = structlog.get_logger(None, module=__name__)
#    # Consumer queues
#    alert
#    authentication_data
#    dpapi_blob
#    dpapi_blob_processed
#    dpapi_masterkey
#    dpapi_masterkey_processed
#    file_data
#    file_data_enriched
#    file_data_plaintext
#    file_information
#    path_list
#    process_category
#    raw_data
#    registry_value

# Standard Libraries
#    # Publisher queues
#    alert
#    authentication_data
#    dpapi_blob_processed
#    dpapi_masterkey_processed
#    file_data
#    file_data_enriched
#    file_data_plaintext
#
#    # All queues
#    alert
#    authentication_data
#    dpapi_blob
#    dpapi_blob_processed
#    dpapi_masterkey
#    dpapi_masterkey_processed
#    file_data
#    file_data_enriched
#    file_data_plaintext
#    file_information
#    path_list
#    process_category
#    raw_data
#    registry_value


async def initRabbitMQ(connectionUri: str) -> None:
    await logger.adebug("Setting up queues")
    connection = await connect_robust(connectionUri)

    async with connection:
        channel = await connection.channel()

        for k in RABBITMQ_QUEUE_BINDINGS.keys():
            b = RABBITMQ_QUEUE_BINDINGS[k]

            await channel.declare_exchange(
                b.Exchange, ExchangeType.DIRECT, durable=True
            )

            # newQueue = await channel.declare_queue(b.Queue, durable=True)
            # await newQueue.bind(b.Exchange, b.RoutingKey)

    await logger.adebug("Done setting up queues")
