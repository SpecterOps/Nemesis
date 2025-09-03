"""DPAPI utility library for Windows Data Protection API operations."""

from .core import Blob, DomainBackupKey, MasterKey, MasterKeyFile
from .crypto import DpapiCrypto, MasterKeyEncryptionKey
from .exceptions import (
    DpapiBlobDecryptionError,
    DpapiError,
    MasterKeyNotDecryptedError,
    MasterKeyNotFoundError,
    StorageError,
)
from .manager import DpapiManager

__all__ = [
    # Main classes
    "Blob",
    "DomainBackupKey",
    "DpapiCrypto",
    "DpapiManager",
    "MasterKey",
    "MasterKeyEncryptionKey",
    "MasterKeyFile",
    # Exceptions
    "DpapiError",
    "MasterKeyNotFoundError",
    "MasterKeyNotDecryptedError",
    "DpapiBlobDecryptionError",
    "StorageError",
]
