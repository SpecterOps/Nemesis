"""Main DPAPI manager class."""

from abc import abstractmethod
from datetime import UTC, datetime
from uuid import UUID

from pydantic import Field, field_validator

from nemesis_dpapi.core import BaseModel
from nemesis_dpapi.keys import DpapiSystemCredential, NtlmHash, Password, Pbkdf2Hash, Sha1Hash
from nemesis_dpapi.types import Sid


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

    def unsubscribe(self, observer: DpapiObserver) -> None:
        """Detach an observer from this subject."""
        if observer in self._observers:
            self._observers.remove(observer)

    def publish(self, event: DpapiEvent) -> None:
        """Notify all observers of an event."""
        for observer in self._observers:
            observer.update(event)
