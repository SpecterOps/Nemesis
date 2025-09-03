"""Main DPAPI manager class."""

from abc import abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID


@dataclass
class NewEncryptedMasterKeyEvent:
    """Event emitted when a new encrypted master key is added"""

    masterkey_guid: UUID
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class NewPlaintextMasterKeyEvent:
    """Event emitted when a new plaintext master key is added"""

    masterkey_guid: UUID
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class NewDomainBackupKeyEvent:
    """Event emitted when a new domain backup key is added"""

    backup_key_guid: UUID
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


type DpapiEvent = NewEncryptedMasterKeyEvent | NewPlaintextMasterKeyEvent | NewDomainBackupKeyEvent


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
