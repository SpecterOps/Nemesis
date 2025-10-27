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


class StorageError(DpapiError):
    """Raised when storage backend operations fail."""

    pass


class DpapiCryptoError(DpapiError):
    """Base exception for DPAPI cryptographic operations."""

    pass


class InvalidBackupKeyError(DpapiCryptoError):
    """Raised when domain backup key is invalid or malformed."""

    pass


class MasterKeyDecryptionError(DpapiCryptoError):
    """Raised when masterkey decryption fails."""

    pass


class BlobParsingError(DpapiError):
    """Raised when DPAPI blob data is invalid or malformed."""

    pass


class BlobDecryptionError(DpapiError):
    """Raised when DPAPI blob decryption fails."""

    pass


class WriteOnceViolationError(StorageError):
    """Raised when attempting to modify a field that already has a value (write-once semantics).

    This exception is raised when an upsert operation tries to change a field that already
    contains a non-NULL value. Write-once semantics ensure that once a field is set to a
    non-NULL value, it cannot be changed to a different value.
    """

    def __init__(self, entity_type: str, entity_id: str, fields: list[str]) -> None:
        """Initialize WriteOnceViolationError.

        Args:
            entity_type: The type of entity (e.g., "masterkey", "backup_key")
            entity_id: The identifier of the entity (e.g., GUID)
            fields: List of field names that have write-once violations
        """
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.fields = fields

        fields_str = ", ".join(f"'{f}'" for f in fields)
        super().__init__(
            f"Write-once violation for {entity_type} {entity_id}: "
            f"field(s) {fields_str} already have values and cannot be modified"
        )
