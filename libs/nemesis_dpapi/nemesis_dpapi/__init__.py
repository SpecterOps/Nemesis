"""DPAPI utility library for Windows Data Protection API operations."""

from .core import Blob, MasterKey, MasterKeyFile, MasterKeyPolicy
from .exceptions import (
    BlobDecryptionError,
    DpapiError,
    MasterKeyDecryptionError,
    MasterKeyNotDecryptedError,
    MasterKeyNotFoundError,
    StorageError,
)
from .keys import (
    CredKey,
    CredKeyHashType,
    DomainBackupKey,
    DpapiSystemCredential,
    MasterKeyEncryptionKey,
    NtlmHash,
    Password,
    Pbkdf2Hash,
    Sha1Hash,
)
from .manager import DpapiManager
from .repositories import MasterKeyFilter

__all__ = [
    # Main classes
    "Blob",
    "DpapiManager",
    "MasterKey",
    "MasterKeyDecryptionError",
    "MasterKeyPolicy",
    "MasterKeyFile",
    "MasterKeyFilter",
    # Keys
    "CredKey",
    "CredKeyHashType",
    "DomainBackupKey",
    "DpapiSystemCredential",
    "MasterKeyEncryptionKey",
    "NtlmHash",
    "Password",
    "Pbkdf2Hash",
    "Sha1Hash",
    # Exceptions
    "BlobDecryptionError",
    "DpapiError",
    "MasterKeyNotFoundError",
    "MasterKeyNotDecryptedError",
    "StorageError",
]
