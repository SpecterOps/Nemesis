"""Custom exceptions for DPAPI operations."""

from uuid import UUID


class DpapiError(Exception):
    """Base exception for DPAPI operations."""

    pass


class MasterKeyNotFoundError(DpapiError):
    """Raised when required masterkey is not present."""

    def __init__(self, masterkey_guid: UUID) -> None:
        super().__init__(f"Masterkey {masterkey_guid} not found")
        self.masterkey_guid = masterkey_guid


class MasterKeyNotDecryptedError(DpapiError):
    """Raised when masterkey exists but plaintext not available."""

    def __init__(self, masterkey_guid: UUID) -> None:
        super().__init__(f"Masterkey {masterkey_guid} found but not decrypted")
        self.masterkey_guid = masterkey_guid


class DpapiBlobDecryptionError(DpapiError):
    """Raised when DPAPI blob decryption fails."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Failed to decrypt DPAPI blob: {reason}")
        self.reason = reason


class StorageError(DpapiError):
    """Raised when storage backend operations fail."""

    pass
