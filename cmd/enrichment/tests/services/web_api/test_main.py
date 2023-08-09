# Standard Libraries
import base64
import json
import logging
import tempfile
from typing import Awaitable, Callable, List

# 3rd Party Libraries
import google.protobuf.message
import nemesiscommon.constants as constants
from enrichment.tasks.web_api import WebAPI
from fastapi import FastAPI
from fastapi.testclient import TestClient
from nemesiscommon.messaging import (
    MessageQueueConsumerInterface,
    MessageQueueProducerInterface,
)
from nemesiscommon.mocks import storage

TEST_ASSESS_ID = "assessment_id"


class MockProducerConsumer(MessageQueueProducerInterface, MessageQueueConsumerInterface):
    def __init__(self, name="", *args, **kwargs):
        self.name = name
        self._vals: List[bytes] = []

    async def Read(self, worker: Callable[[google.protobuf.message.Message], Awaitable[None]]) -> None:
        await worker(self._vals.pop(0))

    async def Send(self, message: bytes) -> None:
        self._vals.append(message)

    async def Close(self) -> None:
        pass

    async def __aenter__(self):
        pass

    async def __aexit__(self, *args, **kwargs) -> None:
        pass


async def test_data_post_authentication_data() -> None:
    app = FastAPI()
    logger = logging.getLogger("test")
    queues = {q: MockProducerConsumer(q) for q in constants.ALL_QUEUES}
    routes = WebAPI(logger, queues, storage.StorageNop(), "assessment_id")
    app.include_router(routes.router)
    client = TestClient(app)

    data = '{"metadata":{"agentId":"test_agent_id","agentType":"beacon","dataType":"authentication_data","source":"domain.com","project":"1234","timestamp":"2023-04-06T20:09:28.686025Z","messageId":"1234"},"data":[{"data":"test_data","type":"creds","uri":"https://domain.com","username":"test_user","notes":"test_notes"}]}'
    data_obj = json.loads(data)
    res = client.post("/data", json=data_obj)
    assert res.status_code == 200

    client = queues[constants.Q_AUTHENTICATION_DATA]
    async with client:

        async def process_message(message: bytes) -> None:
            assert message.decode("utf-8") == data

        await client.Read(process_message)

    out = res.json()
    assert "object_id" in out


async def test_data_post_authentication_data_body() -> None:
    app = FastAPI()
    logger = logging.getLogger("test")
    queues = {q: MockProducerConsumer() for q in constants.ALL_QUEUES}
    routes = WebAPI(logger, queues, storage.StorageNop(), "assessment_id")
    app.include_router(routes.router)
    client = TestClient(app)

    data = '{"metadata":{"agentId":"test_agent_id","agentType":"beacon","dataType":"authentication_data","source":"domain.com","project":"1234","timestamp":"2023-04-06T20:09:28.686025Z","messageId":"1234"},"data":[{"data":"test_data","type":"creds","uri":"https://domain.com","username":"test_user","notes":"test_notes"}]}'
    data_obj = json.loads(data)
    res = client.post("/data", json=data_obj)
    out = res.json()
    assert "object_id" in out


async def test_data_post_file_data_works() -> None:
    app = FastAPI()
    logger = logging.getLogger("test")
    queues = {q: MockProducerConsumer() for q in constants.ALL_QUEUES}
    routes = WebAPI(logger, queues, storage.StorageNop(), "assessment_id")
    app.include_router(routes.router)
    client = TestClient(app)

    data = '{"metadata": {"agent_id": "WILL", "agent_type": "submit_to_nemesis", "automated": false, "data_type": "file_data", "source": "computer.domain.com", "expiration": "2023-07-22T16:19:17.000Z", "project": "ASSESS-TEST", "timestamp": "2023-04-13T16:19:17.000Z"}, "data": [{"path": "/home/max/Programming/ods/sample_files/appsettings.json", "size": 307, "object_id": "1a7443e2-97f4-4996-994c-00cf3ca94cad"}]}'
    data_obj = json.loads(data)
    res = client.post("/data", json=data_obj)
    print(res.text)
    assert res.status_code == 200


async def test_data_post_file_data_body() -> None:
    app = FastAPI()
    logger = logging.getLogger("test")
    queues = {q: MockProducerConsumer() for q in constants.ALL_QUEUES}
    routes = WebAPI(logger, queues, storage.StorageNop(), "assessment_id")
    app.include_router(routes.router)
    client = TestClient(app)

    data = '{"metadata": {"agent_id": "WILL", "agent_type": "submit_to_nemesis", "automated": false, "data_type": "file_data", "source": "computer.domain.com", "expiration": "2023-07-22T16:19:17.000Z", "project": "ASSESS-TEST", "timestamp": "2023-04-13T16:19:17.000Z"}, "data": [{"path": "/home/max/Programming/ods/sample_files/appsettings.json", "size": 307, "object_id": "1a7443e2-97f4-4996-994c-00cf3ca94cad"}]}'
    data_obj = json.loads(data)
    res = client.post("/data", json=data_obj)
    out = res.text
    assert "object_id" in out


async def test_data_post_file_data() -> None:
    app = FastAPI()
    logger = logging.getLogger("test")
    queues = {q: MockProducerConsumer() for q in constants.ALL_QUEUES}
    routes = WebAPI(logger, queues, storage.StorageNop(), "assessment_id")
    app.include_router(routes.router)
    client = TestClient(app)

    data = '{"metadata": {"agent_id": "WILL", "agent_type": "submit_to_nemesis", "automated": false, "data_type": "file_data", "source": "computer.domain.com", "expiration": "2023-07-22T16:19:17.000Z", "project": "ASSESS-TEST", "timestamp": "2023-04-13T16:19:17.000Z"}, "data": [{"path": "/home/max/Programming/ods/sample_files/appsettings.json", "size": 307, "object_id": "1a7443e2-97f4-4996-994c-00cf3ca94cad"}]}'
    data_obj = json.loads(data)
    res = client.post("/data", json=data_obj)

    client = queues[constants.Q_FILE_DATA]
    async with client:

        async def process_message(message: bytes) -> None:
            print(message.decode("utf-8"), data)
            assert message.decode("utf-8") == data

        await client.Read(process_message)

    out = res.json()
    assert "object_id" in out


async def test_file_post() -> None:
    app = FastAPI()
    logger = logging.getLogger("test")
    queues = {q: MockProducerConsumer() for q in constants.ALL_QUEUES}
    stg = storage.StorageLocal()
    routes = WebAPI(logger, queues, stg, "assessment_id")
    app.include_router(routes.router)
    client = TestClient(app)

    temp_file = tempfile.TemporaryFile()
    temp_file.write(b"test")
    temp_file.seek(0)

    res = client.post("/file", files={"file": temp_file})

    res_out = res.json()

    assert res.status_code == 200
    assert "object_id" in res_out
    assert stg.exists(res_out["object_id"])


async def test_file_get() -> None:
    app = FastAPI()
    queues = {q: MockProducerConsumer() for q in constants.ALL_QUEUES}
    stg = storage.StorageLocal()
    routes = WebAPI(None, queues, stg, "assessment_id")
    app.include_router(routes.router)
    client = TestClient(app)

    TEST_STR = "test".encode("utf-8")

    res = client.post("/file", data=TEST_STR)

    res_out = res.json()
    id_ = res_out["object_id"]
    id_b64 = base64.urlsafe_b64encode(id_.encode("utf-8")).decode("utf-8")

    res_g = client.get(f"/data?storage_id={id_b64}")
    assert res_g.status_code == 200
    assert res_g.content == TEST_STR


async def test_download() -> None:
    app = FastAPI()
    queues = {q: MockProducerConsumer() for q in constants.ALL_QUEUES}
    stg = storage.StorageLocal(TEST_ASSESS_ID)
    routes = WebAPI(None, queues, stg, TEST_ASSESS_ID)
    app.include_router(routes.router)
    client = TestClient(app)

    TEST_STR = "test".encode("utf-8")

    res = client.post("/file", data=TEST_STR)

    res_out = res.json()
    id_ = res_out["object_id"]

    res_g = client.get(f"/download/{id_}")
    assert res_g.status_code == 200
    assert res_g.headers["Content-Disposition"] == f'attachment; filename="{id_}"'
    assert res_g.headers["Content-Type"] == "application/octet-stream"


async def test_download_pdf() -> None:
    app = FastAPI()
    queues = {q: MockProducerConsumer() for q in constants.ALL_QUEUES}
    stg = storage.StorageLocal(TEST_ASSESS_ID)
    routes = WebAPI(None, queues, stg, TEST_ASSESS_ID)
    app.include_router(routes.router)
    client = TestClient(app)

    TEST_STR = "test".encode("utf-8")

    res = client.post("/file", data=TEST_STR)

    res_out = res.json()
    id_ = res_out["object_id"]

    res_g = client.get(f"/download/{id_}?name=test.pdf")
    assert res_g.status_code == 200
    assert res_g.headers["Content-Disposition"] == f'inline; filename="{id_}"'
    assert res_g.headers["Content-Type"] == "application/pdf"
