# Standard Libraries
import logging
from types import TracebackType
from typing import Optional, Type, Union

# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
import pytest
import structlog
from enrichment.lib.nemesis_db import (
    AuthenticationData,
    DpapiBlob,
    ExtractedHash,
    NemesisDbInterface,
    Project,
    RegistryObject,
    ServiceColumn,
)
from nemesiscommon.messaging import MessageQueueProducerInterface


class MockNemesisDb(NemesisDbInterface):
    async def add_project(self, project: Project) -> None:
        pass

    async def add_authentication_data(self, auth_data: AuthenticationData) -> None:
        pass

    async def add_extracted_hash(self, auth_data: ExtractedHash) -> None:
        pass

    async def add_dpapi_blob(self, dpapi_blob: DpapiBlob) -> None:
        pass

    async def add_registry_object(self, registry_object: RegistryObject) -> None:
        pass

    async def add_service(self, metadata: pb.Metadata, service_name: str) -> None:
        pass

    async def add_service_property(self, metadata: pb.Metadata, service_name: str, value_name: str, value: Union[int, str]) -> None:
        pass

    async def add_host_info(self, os_info) -> None:
        pass

    async def add_filesystem_object(self, file_info) -> None:
        pass


class MockMessageProducer(MessageQueueProducerInterface):
    message_count = 0

    async def Send(self, message: bytes) -> None:
        self.message_count += 1
        pass

    async def Close(self) -> None:
        pass

    async def __aenter__(self):
        pass

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        pass


@pytest.fixture
def nemesis_db() -> MockNemesisDb:
    return MockNemesisDb()


@pytest.fixture
def message_producer() -> MockMessageProducer:
    return MockMessageProducer()


@pytest.fixture
def logger() -> logging.Logger:
    log = logging.getLogger("test")
    log.addHandler(logging.NullHandler())
    return log
