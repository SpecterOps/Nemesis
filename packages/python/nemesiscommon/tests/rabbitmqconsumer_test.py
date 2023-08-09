# Standard Libraries
from unittest.mock import AsyncMock, Mock, NonCallableMock, patch

# 3rd Party Libraries
import aio_pika
import pytest
from nemesiscommon.messaging_rabbitmq import NemesisRabbitMQProducer
from nemesiscommon.NemesisRabbitMQConsumer import NemesisRabbitMQConsumer


class MockMessage:
    def __init__(self, routing_key, body):
        self.routing_key = routing_key
        self.body = body

    def process(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        pass


URL = 'amqp://username:password@hostname:5672/virtualhost'
QUEUE_FROM = 'receive_queue'
QUEUE_TO = 'send_queue'

DATA_BYTES = b'{"test": "hello world"}'
DATA_DICT = {'test': 'hello world'}


async def async_repeat(data):
    while True:
        yield data


class MockManager:
    def __init__(self):
        self.iterator = AsyncMock()
        self.iterator.__aenter__.return_value = async_repeat(
            MockMessage(QUEUE_FROM, DATA_BYTES)
        )

        self.queue = NonCallableMock(spec=aio_pika.RobustQueue)
        self.queue.iterator = Mock(return_value=self.iterator)

        self.channel = NonCallableMock(spec=aio_pika.RobustChannel)
        self.channel.get_queue = AsyncMock(return_value=self.queue)
        self.exchange = self.channel.default_exchange = Mock(
            spec=aio_pika.RobustExchange
        )

        self.connection = NonCallableMock(spec=aio_pika.RobustConnection)
        self.connection.channel = AsyncMock(return_value=self.channel)

        self.connect_robust = AsyncMock(return_value=self.connection)

    def patch(self):
        return patch('aio_pika.connect_robust', self.connect_robust)


@pytest.mark.asyncio
async def test_receive():
    mocks = MockManager()

    with mocks.patch():
        publisher = await NemesisRabbitMQProducer.create(URL, "test", "test", {})
        async with publisher:
            publisher.Send(b"asdf")

        client = await NemesisRabbitMQConsumer.create(URL, "test", {})
        async with client:
            async def process_message(self, message: bytes) -> None:
                print(message)
            client.Read(process_message)

    # assert message.queue_name == QUEUE_FROM
    # assert message.data == DATA_DICT


def test_answer():
    assert 5 == 5
