"""Main DPAPI manager class."""

from abc import abstractmethod
from datetime import UTC, datetime
from logging import getLogger
from typing import get_args
from uuid import UUID

from dapr.clients import DaprClient
from dapr.clients.grpc._response import TopicEventResponse, TopicEventResponseStatus
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


DAPR_PUBSUB_NAME = "pubsub"
DAPR_DPAPI_EVENT_TOPIC = "dpapi_events"

DPAPI_EVENT_CLASSES = {cls.__name__: cls for cls in get_args(DpapiEvent.__value__)}


class TypedDpapiEvent(BaseModel):
    """Wrapper class for DpapiEvent with type information for deserialization."""

    type_name: str
    event: DpapiEvent

    @model_validator(mode="before")
    @classmethod
    def deserialize_event(cls, data: dict) -> dict:
        if isinstance(data, dict) and "type_name" in data and "event" in data:
            event_class = DPAPI_EVENT_CLASSES.get(data["type_name"])
            if event_class and isinstance(data["event"], dict):
                data["event"] = event_class(**data["event"])
        return data


class DpapiObserver:
    """Base class for DPAPI event observers."""

    @abstractmethod
    def update(self, event: DpapiEvent) -> None:
        """Called when an observed event occurs."""
        pass


class Publisher:
    """Abstract base class for subjects in the observer pattern."""

    def __init__(self):
        self._observers: list[DpapiObserver] = []

    def subscribe(self, observer: DpapiObserver) -> None:
        """Attach an observer to this subject."""
        if observer not in self._observers:
            self._observers.append(observer)

    def publish(self, event: DpapiEvent) -> None:
        """Notify all observers of an event."""
        for observer in self._observers:
            observer.update(event)


class DaprPublisher(Publisher):
    """DPAPI event publisher using Dapr pub/sub."""

    def __init__(self, dapr_client: DaprClient):
        super().__init__()
        self._dapr_client = dapr_client

    def publish(self, event: DpapiEvent) -> None:
        """Publish an event to all subscribed observers via Dapr pub/sub."""

        event_type = event.__class__.__name__
        new_event = TypedDpapiEvent(type_name=event_type, event=event)

        logger.debug("Publishing event of type %s to Dapr: %s", event_type)
        self._dapr_client.publish_event(
            pubsub_name=DAPR_PUBSUB_NAME,
            topic_name=DAPR_DPAPI_EVENT_TOPIC,
            data=new_event.model_dump_json(),
            data_content_type="application/json",
        )

    def process_message(self, evnt: TypedDpapiEvent) -> TopicEventResponse:
        """Process incoming Dapr pub/sub messages."""

        logger.debug("Processing event of type %s", evnt.type_name)

        for observer in self._observers:
            observer.update(evnt.event)

        return TopicEventResponse(TopicEventResponseStatus.success)

    def start(self) -> None:
        """Start the Dapr client (if needed)."""

        close_fn = self._dapr_client.subscribe_with_handler(
            pubsub_name=DAPR_PUBSUB_NAME,
            topic=DAPR_DPAPI_EVENT_TOPIC,
            handler_fn=lambda event: self.process_message(event),
            # dead_letter_topic="TOPIC_A_DEAD",
        )

        close_fn()
