"""DPAPI utility library for Windows Data Protection API operations."""

from .core import Blob, DomainBackupKey, DpapiSystemCredential, MasterKey, MasterKeyFile
from .crypto import CredKey, CredKeyHashType, DpapiCrypto, MasterKeyEncryptionKey
from .exceptions import (
    DpapiBlobDecryptionError,
    DpapiError,
    MasterKeyDecryptionError,
    MasterKeyNotDecryptedError,
    MasterKeyNotFoundError,
    StorageError,
)
from .manager import DpapiManager
from .repositories import MasterKeyFilter

__all__ = [
    # Main classes
    "Blob",
    "CredKey",
    "CredKeyHashType",
    "DomainBackupKey",
    "DpapiCrypto",
    "DpapiManager",
    "DpapiSystemCredential",
    "MasterKey",
    "MasterKeyDecryptionError",
    "MasterKeyEncryptionKey",
    "MasterKeyFile",
    "MasterKeyFilter",
    # Exceptions
    "DpapiError",
    "MasterKeyNotFoundError",
    "MasterKeyNotDecryptedError",
    "DpapiBlobDecryptionError",
    "StorageError",
]
