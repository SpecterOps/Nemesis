# Standard Libraries
import asyncio
from abc import abstractmethod
from types import TracebackType
from typing import Awaitable, Callable, Generic, Optional, Type, TypeVar

# 3rd Party Libraries
import aio_pika
import structlog
from aio_pika import (
    DeliveryMode,
    ExchangeType,
    Message,
    RobustChannel,
    RobustConnection,
    RobustExchange,
)
from aio_pika.abc import (
    AbstractChannel,
    AbstractConnection,
    AbstractIncomingMessage,
    AbstractQueue,
)
from google.protobuf.message import Message as ProtobufMessage
from nemesiscommon.constants import RABBITMQ_QUEUE_BINDINGS, NemesisQueue
from nemesiscommon.messaging import (
    MessageQueueConsumerInterface,
    MessageQueueProducerInterface,
)
from nemesiscommon.tasking import TaskInterface

T = TypeVar("T", bound=ProtobufMessage)
logger = structlog.get_logger(module=__name__)


class NemesisRabbitMQProducer(MessageQueueProducerInterface):
    __connection: RobustConnection
    __channel: RobustChannel
    __exchange: RobustExchange
    __queue: NemesisQueue
    __routingKey: str

    def __init__(
        self,
        connection: RobustConnection,
        channel: RobustChannel,
        exchange: RobustExchange,
        queue: NemesisQueue,
        routingKey: str,
    ) -> None:
        self.__connection = connection
        self.__channel = channel
        self.__exchange = exchange
        self.__queue = queue
        self.__routingKey = routingKey

    @classmethod
    async def create(self, uri: str, queue: NemesisQueue) -> "NemesisRabbitMQProducer":
        connection = await aio_pika.connect_robust(uri)
        channel = await connection.channel()

        # Ensure the exchange exists
        exchangeObj = await channel.declare_exchange(
            RABBITMQ_QUEUE_BINDINGS[queue].Exchange,
            ExchangeType.DIRECT,
            durable=True,
        )

        return self(
            connection,
            channel,
            exchangeObj,
            queue,
            RABBITMQ_QUEUE_BINDINGS[queue].RoutingKey,
        )

    async def Send(self, message: bytes) -> None:
        await logger.adebug(
            "Sending message to RabbitMQ",
            exchange=self.__exchange.name,
            routing_key=self.__routingKey,
            queue=self.__queue,
        )

        q_msg = Message(
            message,
            delivery_mode=DeliveryMode.PERSISTENT,
        )

        await self.__exchange.publish(q_msg, routing_key=self.__routingKey)

    async def Close(self) -> None:
        self.__exchange
        if not self.__channel or self.__channel.is_closed:
            return
        else:
            await self.__channel.close()

        if not self.__connection or self.__connection.is_closed:
            return

        await self.__connection.close()

    async def __aenter__(self):
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        await self.Close()


class NemesisRabbitMQConsumer(MessageQueueConsumerInterface, Generic[T]):
    __connection: AbstractConnection
    __channel: AbstractChannel
    __queue: AbstractQueue
    __queueType: Type[T]

    def __init__(
        self,
        connection: AbstractConnection,
        channel: AbstractChannel,
        queue: AbstractQueue,
        inputQtype: Type[T],
    ) -> None:
        self.__connection = connection
        self.__channel = channel
        self.__queue = queue
        self.__queueType = inputQtype

    @classmethod
    async def create(
        cls,
        uri: str,
        queue: str,
        inputQtype: Type[T],
        service_id: str,
        num_events: int = 250,
    ):
        connection = await aio_pika.connect_robust(uri)
        channel = await connection.channel()
        await channel.set_qos(num_events)

        # Ensure the queue exists
        rabbitQueueName = RABBITMQ_QUEUE_BINDINGS[queue].Queue + "." + service_id

        queueObj = await channel.declare_queue(rabbitQueueName, durable=True)
        await queueObj.bind(
            RABBITMQ_QUEUE_BINDINGS[queue].Exchange,
            RABBITMQ_QUEUE_BINDINGS[queue].RoutingKey,
        )

        return cls(connection, channel, queueObj, inputQtype)

    async def Read(self, worker: Callable[[T], Awaitable[None]]) -> None:
        async def on_message(message: AbstractIncomingMessage) -> None:
            try:
                obj = self.__queueType()
                obj.ParseFromString(message.body)
                await worker(obj)

                if not message.processed:
                    await message.ack()
            except Exception as e:
                await logger.aexception(
                    e,
                    message="Exception thrown while processing the queue",
                    queue=self.__queue.name,
                )

                if not message.processed:
                    # If an unhandled exception happens, err on the side of not losing data and resubmit to queue
                    # This could lead to a loop where the same troublesome message keeps getting resubmitted due to
                    # it never parsing correctly
                    # await message.reject(requeue=True)

                    await message.ack()

        await logger.adebug("Waiting for messages", queue=self.__queue.name)
        await self.__queue.consume(callback=on_message, no_ack=False)

    async def __aenter__(self):
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        await self.Close()

    async def Close(self) -> None:
        if not self.__channel or self.__channel.is_closed:
            return
        else:
            await self.__channel.close()

        if not self.__connection or self.__connection.is_closed:
            return

        await self.__connection.close()


class SingleQueueRabbitMQWorker(TaskInterface):
    inputQueue: MessageQueueConsumerInterface

    def __init__(self, inputQ: MessageQueueConsumerInterface):
        self.inputQueue = inputQ

    async def run(self) -> None:
        await self.inputQueue.Read(self.process_message)
        await asyncio.Future()

    @abstractmethod
    async def process_message(self, message: T) -> None:
        raise NotImplementedError
