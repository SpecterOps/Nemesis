"""Main DPAPI manager class."""

import asyncio
import json
from abc import abstractmethod
from datetime import UTC, datetime
from logging import getLogger
from typing import get_args
from uuid import UUID

from common.queues import DPAPI_EVENTS_TOPIC, DPAPI_PUBSUB
from dapr.aio.clients import DaprClient
from dapr.clients.grpc._response import TopicEventResponse, TopicEventResponseStatus
from dapr.clients.grpc.subscription import SubscriptionMessage
from pydantic import Field, field_validator, model_validator

from nemesis_dpapi.core import BaseModel
from nemesis_dpapi.keys import DpapiSystemCredential, NtlmHash, Password, Pbkdf2Hash, Sha1Hash
from nemesis_dpapi.types import Sid

logger = getLogger(__name__)


class NewEncryptedMasterKeyEvent(BaseModel):
    """Event emitted when a new encrypted master key is added"""

    masterkey_guid: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class NewPlaintextMasterKeyEvent(BaseModel):
    """Event emitted when a new plaintext master key is added"""

    masterkey_guid: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class NewDomainBackupKeyEvent(BaseModel):
    """Event emitted when a new domain backup key is added"""

    backup_key_guid: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class NewDpapiSystemCredentialEvent(BaseModel):
    """Event emitted when a new DPAPI system credential is added"""

    credential: DpapiSystemCredential
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class NewPasswordDerivedCredentialEvent(BaseModel):
    """Event emitted when a new password-derived credential is added. This includes
    Password, NTLM hash, SHA1 hash, and PBKDF2 hash credentials."""

    type: str
    credential: Password | NtlmHash | Sha1Hash | Pbkdf2Hash
    user_sid: Sid | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("type")
    @classmethod
    def validate_type_matches_credential(cls, v, info):
        """Validate that the type field matches the credential class name."""
        if "credential" in info.data:
            credential = info.data["credential"]
            expected_type = credential.__class__.__name__
            if v != expected_type:
                raise ValueError(f"Type '{v}' does not match credential class name '{expected_type}'")
        return v


type DpapiEvent = (
    NewEncryptedMasterKeyEvent
    | NewPlaintextMasterKeyEvent
    | NewDomainBackupKeyEvent
    | NewDpapiSystemCredentialEvent
    | NewPasswordDerivedCredentialEvent
)


DPAPI_EVENT_CLASSES = {cls.__name__: cls for cls in get_args(DpapiEvent.__value__)}

subscription_started = False


class TypedDpapiEvent(BaseModel):
    """Wrapper class for DpapiEvent with type information for deserialization."""

    type_name: str
    evnt: DpapiEvent

    @model_validator(mode="before")
    @classmethod
    def deserialize_event(cls, data: dict) -> dict:
        if isinstance(data, dict) and "type_name" in data and "evnt" in data:
            event_class = DPAPI_EVENT_CLASSES.get(data["type_name"])
            if event_class and isinstance(data["evnt"], dict):
                data["evnt"] = event_class(**data["evnt"])
        return data


class DpapiObserver:
    """Base class for DPAPI event observers."""

    @abstractmethod
    async def update(self, event: DpapiEvent) -> None:
        """Called when an observed event occurs."""
        pass


class DpapiEventPublisher:
    """Abstract base class for DPAPI event publishers."""

    @abstractmethod
    async def register_subscriber(self, observer: DpapiObserver) -> None:
        """Attach an observer to this publisher."""
        pass

    @abstractmethod
    async def publish_event(self, event: DpapiEvent) -> None:
        """Publish an event to all subscribed observers."""
        pass


class InMemoryPublisher(DpapiEventPublisher):
    """In-memory publisher using the observer pattern."""

    def __init__(self):
        self._observers: list[DpapiObserver] = []

    async def register_subscriber(self, observer: DpapiObserver) -> None:
        """Attach an observer to this publisher."""
        if observer not in self._observers:
            self._observers.append(observer)

    async def publish_event(self, event: DpapiEvent) -> None:
        """Notify all observers of an event."""
        for observer in self._observers:
            await observer.update(event)


class DaprDpapiEventPublisher(DpapiEventPublisher):
    """DPAPI event publisher using Dapr pub/sub."""

    def __init__(self, dapr_client: DaprClient):
        self._dapr_client = dapr_client
        self._observers: list[DpapiObserver] = []
        self._background_task = None

    async def register_subscriber(self, observer: DpapiObserver) -> None:
        """Attach an observer and start the Dapr subscription if not already started."""

        logger.debug(f"Subscribing Dapr observer: {observer.__class__.__name__}")
        self._observers.append(observer)

        global subscription_started
        if not subscription_started:
            subscription_started = True
            self._background_task = asyncio.create_task(self._start_subscription())

    async def publish_event(self, event: DpapiEvent) -> None:
        """Publish an event to all subscribed observers via Dapr pub/sub."""

        event_type = event.__class__.__name__
        new_event = TypedDpapiEvent(type_name=event_type, evnt=event)

        logger.debug(f"Publishing event of type {event_type} to Dapr")
        await self._dapr_client.publish_event(
            pubsub_name=DPAPI_PUBSUB,
            topic_name=DPAPI_EVENTS_TOPIC,
            data=new_event.model_dump_json(),
            data_content_type="application/json",
        )

    async def process_message(self, evnt: SubscriptionMessage) -> TopicEventResponse:
        """Process incoming Dapr pub/sub messages."""

        logger.debug(f"Processing event of type {evnt.type()}.  JSON: {json.dumps(evnt.data())}")

        # type_name = evnt.type()
        typed_dpapi_event_dict = evnt.data()
        if not isinstance(typed_dpapi_event_dict, dict):
            logger.error(f"Received event data is not a dictionary: {typed_dpapi_event_dict}")
            return TopicEventResponse(TopicEventResponseStatus.drop)

        typed_dpapi_event = TypedDpapiEvent(**typed_dpapi_event_dict)

        # convert the dict to the appropriate event class using DPAPI_EVENT_CLASSES
        event_class = DPAPI_EVENT_CLASSES.get(typed_dpapi_event.type_name)
        if event_class:
            dpapi_event = event_class(**typed_dpapi_event_dict["evnt"])
        else:
            logger.error(f"Unknown event type received: {typed_dpapi_event.type_name}")
            return TopicEventResponse(TopicEventResponseStatus.drop)

        for observer in self._observers:
            # not sure why `await observer.update(dpapi_event)` interrupts the retroactive DPAPI
            #   decryption flow but it does, so don't change this :)
            asyncio.run_coroutine_threadsafe(observer.update(dpapi_event), self._loop)

        return TopicEventResponse(TopicEventResponseStatus.success)

    async def _start_subscription(self) -> None:
        """Start the Dapr client (if needed)."""

        logger.info("Starting Dapr subscriber handler...")
        close_fn = await self._dapr_client.subscribe_with_handler(
            pubsub_name=DPAPI_PUBSUB,
            topic=DPAPI_EVENTS_TOPIC,
            handler_fn=self.process_message,
            # dead_letter_topic="TOPIC_A_DEAD",
        )

        # wait indefinitely
        await asyncio.Event().wait()

        close_fn()
