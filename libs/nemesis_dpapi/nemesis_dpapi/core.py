"""Core data types used in the DPAPI library"""

from __future__ import annotations

import json
import re
import struct
from enum import Enum, IntFlag
from pathlib import Path
from typing import TYPE_CHECKING, Self
from uuid import UUID

from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.Hash import SHA1
from dpapick3 import blob as dpapick3_blob
from impacket.dpapi import (
    DPAPI_BLOB,
    DPAPI_DOMAIN_RSA_MASTER_KEY,
    PRIVATE_KEY_BLOB,
    PVK_FILE_HDR,
    privatekeyblob_to_pkcs1,
)
from impacket.dpapi import MasterKey as ImpacketMasterKey
from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict

from .exceptions import BlobDecryptionError, BlobParsingError, InvalidBackupKeyError, MasterKeyDecryptionError

if TYPE_CHECKING:
    from .keys import DomainBackupKey, MasterKeyEncryptionKey

DEFAULT_BLOB_PROVIDER_GUID = UUID("DF9D8CD0-1501-11D1-8C7A-00C04FC297EB")


class BaseModel(PydanticBaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    def to_json(self, **kwargs) -> str:
        """Serialize model to JSON string."""
        return self.model_dump_json(**kwargs)

    @classmethod
    def from_json(cls, data: str, **kwargs):
        """
        Deserialize a JSON string into a model instance.
        kwargs are passed to `json.loads`.
        """
        parsed = json.loads(data, **kwargs)
        return cls.model_validate(parsed)


class FlagMixin:
    def has_any(self: Self, flags: Self) -> bool:
        """True if *any* bit in `flags` is set in `self`."""
        return bool(self & flags)

    def has_all(self: Self, flags: Self) -> bool:
        """True if *all* bits in `flags` are set in `self`."""
        return (self & flags) == flags

    def enable(self: Self, flags: Self) -> Self:
        """Return self | flags."""
        return self | flags

    def disable(self: Self, flags: Self) -> Self:
        """Return self with `flags` cleared."""
        return self & ~flags


class MasterKeyPolicy(FlagMixin, IntFlag):
    """Policy bits for DPAPI masterkey."""

    NONE = 0x0  # No special policy
    LOCAL_BACKUP = 0x1  # Policy bit for local only (no DC) backup
    NO_BACKUP = 0x2  # Policy bit for NO backup (Win95)
    DPAPI_OWF = 0x4  # Use the DPAPI One way function of the password (SHA_1(pw))


class MasterKeyType(str, Enum):
    """Type of DPAPI masterkey, which determines the decryption method.

    This classification is based on the account type that generated the masterkey
    and determines which credentials or keys are needed for decryption.
    """

    UNKNOWN = "unknown"  # Masterkey type could not be determined from the file path
    USER = "user"  # User-level masterkey (domain or local user account) - decrypted with user password and/or domain backup key
    SYSTEM = "system"  # System-level masterkey (SYSTEM, LocalService, or NetworkService) - decrypted with DPAPI_SYSTEM machine key
    SYSTEM_USER = "system_user"  # Machine's DPAPI SYSTEM user masterkey - decrypted with DPAPI_SYSTEM user key

    @classmethod
    def from_path(cls, path: str | None) -> MasterKeyType:
        """Determine the user account type from a masterkey file path.

        Args:
            path: The file path to the masterkey file

        Returns:
            MasterKeyType based on the path pattern

        Examples:
            - C:\\Users\\username\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-...\\{GUID} -> USER
            - C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\... -> SYSTEM
            - C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\... -> SYSTEM_USER
            - C:\\Windows\\ServiceProfiles\\LocalService\\... -> SYSTEM
            - C:\\Windows\\ServiceProfiles\\NetworkService\\... -> SYSTEM
        """
        if not path:
            return cls.UNKNOWN

        # Normalize path to lowercase and use forward slashes for easier matching
        normalized_path = path.lower().replace("\\", "/")

        # Check for SYSTEM account with User subdirectory (SYSTEM_USER)
        # Pattern: .../Windows/System32/Microsoft/Protect/S-1-5-18/User/...
        if re.search(r"/windows/system32/microsoft/protect/s-1-5-18/user/", normalized_path):
            return cls.SYSTEM_USER

        # Check for SYSTEM account patterns (SYSTEM, LocalService, NetworkService)
        # Pattern: .../Windows/System32/Microsoft/Protect/S-1-5-18/...
        if re.search(r"/windows/system32/microsoft/protect/s-1-5-18/", normalized_path):
            return cls.SYSTEM

        # Check for LocalService or NetworkService in ServiceProfiles
        # Pattern: .../Windows/ServiceProfiles/(LocalService|NetworkService)/...
        if re.search(r"/windows/serviceprofiles/(localservice|networkservice)/", normalized_path):
            return cls.SYSTEM

        # Check for user profiles with DPAPI protect directory
        # Pattern: .../Users/.../AppData/Roaming/Microsoft/Protect/S-1-5-21-.../...
        if re.search(r"/users/.+/appdata/roaming/microsoft/protect/s-1-5-21-[\d-]+/[0-9a-f-]+", normalized_path):
            return cls.USER

        # Fallback: Check for any user profile with Microsoft Protect
        if re.search(r"/users/.+/appdata/roaming/microsoft/protect/", normalized_path):
            return cls.USER

        # Default to UNKNOWN if we can't determine the type
        return cls.UNKNOWN


class MasterKey(BaseModel):
    """Represents a DPAPI masterkey.

    Attributes:
        guid: Unique identifier for this masterkey.
        encrypted_key_user: Masterkey encrypted with the user's password-derived key.
        encrypted_key_backup: Masterkey encrypted with the domain backup key.
        backup_key_guid: GUID of the domain backup key used to encrypt this masterkey.
        plaintext_key: Decrypted masterkey data.
        plaintext_key_sha1: SHA1 hash of the plaintext masterkey. AKA the Master Key (MK) Encryption Key.
        masterkey_type: Type of user account this masterkey belongs to.
    """

    guid: UUID
    masterkey_type: MasterKeyType
    encrypted_key_usercred: bytes | None = None
    encrypted_key_backup: bytes | None = None
    plaintext_key: bytes | None = None
    plaintext_key_sha1: bytes | None = None
    backup_key_guid: UUID | None = None

    @property
    def is_decrypted(self) -> bool:
        """Check if masterkey has been decrypted."""
        return self.plaintext_key is not None

    def __str__(self) -> str:
        """Return a string representation of the MasterKey with all properties."""
        lines = [
            f"MasterKey({self.guid})",
            f"  guid: {self.guid}",
            f"  encrypted_key_usercred: {self.encrypted_key_usercred.hex() if self.encrypted_key_usercred else None}",
            f"  encrypted_key_backup: {self.encrypted_key_backup.hex() if self.encrypted_key_backup else None}",
            f"  plaintext_key: {self.plaintext_key.hex() if self.plaintext_key else None}",
            f"  plaintext_key_sha1: {self.plaintext_key_sha1.hex() if self.plaintext_key_sha1 else None}",
            f"  backup_key_guid: {self.backup_key_guid}",
            f"  masterkey_type: {self.masterkey_type.value}",
        ]
        return "\r\n".join(lines)

    def decrypt(self, master_key_encryption_key: MasterKeyEncryptionKey) -> MasterKey:
        """Decrypt the master key using the provided master key encryption key.

        Args:
            master_key_encryption_key: The 20-byte SHA1 hash used to decrypt the master key

        Returns:
            A new MasterKey instance with decrypted plaintext_key and plaintext_key_sha1

        Raises:
            ValueError: If encrypted_key_usercred is None
            MasterKeyDecryptionError: If decryption fails
        """
        if self.encrypted_key_usercred is None:
            raise ValueError("No encrypted user credential key available for decryption")

        mk = ImpacketMasterKey(self.encrypted_key_usercred)
        plaintext_mk = mk.decrypt(master_key_encryption_key.key.value)

        if not plaintext_mk:
            raise MasterKeyDecryptionError("Decryption failed")

        plaintext_key_sha1 = SHA1.new(plaintext_mk).digest()

        return self.model_copy(
            update={
                "plaintext_key": plaintext_mk,
                "plaintext_key_sha1": plaintext_key_sha1,
            }
        )


class Blob(BaseModel):
    """Represents a DPAPI encrypted blob.

    Structure representation comes from parsing in SPCryptProtect and SPCryptUnprotect in crypt32p.cpp.
    """

    model_config = {"frozen": True}

    outerVersion: int
    provider_guid: UUID

    version: int
    masterkey_guid: UUID
    prompt_flags: int
    description: str
    encryption_algorithm_id: int
    encryption_algorithm_key_size: int
    encryption_key: bytes
    encryption_salt: bytes
    mac_algorithm_id: int
    mac_algorithm_key_size: int
    mac_key: bytes
    encrypted_data: bytes
    mac: bytes  # MAC signature. Includes all data from the beginning of the structure through encrypted_data

    # Raw bytes of the entire blob
    raw_bytes: bytes

    @classmethod
    def from_file(cls, file_path: str | Path) -> Blob:
        """Parse a DPAPI blob from a file path.

        Args:
            file_path: Path to the blob file

        Returns:
            Blob instance with parsed data

        Raises:
            ValueError: If blob format is invalid
            FileNotFoundError: If file doesn't exist
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Blob file not found: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        return cls.from_bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> Blob:
        """Parse a DPAPI blob from raw bytes.

        Args:
            data: Raw blob bytes

        Returns:
            Blob instance with parsed data

        Raises:
            ValueError: If blob format is invalid
        """

        def _parse_guid(data: bytes) -> UUID:
            # '<' = little-endian for first 3 fields, '>' = big-endian for last field
            data1, data2, data3 = struct.unpack("<IHH", data[:8])
            data4 = data[8:16]  # Keep as bytes (big-endian)

            return UUID(f"{data1:08x}-{data2:04x}-{data3:04x}-{data4[0]:02x}{data4[1]:02x}-{data4[2:].hex()}")

        try:
            dpapi_blob = DPAPI_BLOB(data)
        except Exception as e:
            raise BlobParsingError(f"Failed to parse DPAPI blob: {e}") from e

        # Convert impacket DPAPI_BLOB fields to our Blob class fields
        # Parse Windows GUIDs from bytes to UUID
        masterkey_guid_bytes = dpapi_blob["GuidMasterKey"]
        masterkey_guid = _parse_guid(masterkey_guid_bytes)

        provider_guid_bytes = dpapi_blob["GuidCredential"]
        provider_guid = _parse_guid(provider_guid_bytes)

        # Validate versions are both 1
        if dpapi_blob["Version"] != 1:
            raise BlobParsingError(f"Invalid outer version: {dpapi_blob['Version']}")
        if dpapi_blob["MasterKeyVersion"] != 1:
            raise BlobParsingError(f"Invalid master key version: {dpapi_blob['MasterKeyVersion']}")

        # Validate the provider GUID is DF9D8CD0-1501-11D1-8C7A-00C04FC297EB
        if provider_guid != DEFAULT_BLOB_PROVIDER_GUID:
            raise BlobParsingError(f"Invalid provider GUID: {provider_guid}")

        description = ""
        if dpapi_blob["Description"]:
            description = dpapi_blob["Description"].decode("utf-16le", errors="ignore").rstrip("\x00")

        return cls(
            outerVersion=dpapi_blob["Version"],
            provider_guid=provider_guid,
            version=dpapi_blob["MasterKeyVersion"],
            masterkey_guid=masterkey_guid,
            prompt_flags=dpapi_blob["Flags"],
            description=description,
            encryption_algorithm_id=dpapi_blob["CryptAlgo"],
            encryption_algorithm_key_size=dpapi_blob["CryptAlgoLen"],
            # Yes, this is intended. Impacket incorrectly parses the salt
            # as the encryption key. The encryption key field comes first,
            # then the salt
            encryption_key=dpapi_blob["HMacKey"],
            encryption_salt=dpapi_blob["Salt"],
            mac_algorithm_id=dpapi_blob["HashAlgo"],
            mac_algorithm_key_size=dpapi_blob["HashAlgoLen"],
            mac_key=dpapi_blob["HMac"],
            encrypted_data=dpapi_blob["Data"],
            mac=dpapi_blob["Sign"],
            raw_bytes=data,
        )

    def decrypt(self, masterkey: MasterKey, entropy: bytes | None = None) -> bytes:
        """Decrypt the blob using the provided master key.

        Args:
            masterkey: The decrypted MasterKey instance to use for decryption
            entropy: Optional entropy data used during encryption/decryption

        Returns:
            Decrypted blob data as bytes

        Raises:
            ValueError: If masterkey is not decrypted or decryption fails
        """
        if not masterkey.is_decrypted:
            raise ValueError("Master key must be decrypted before use")

        if masterkey.plaintext_key_sha1 is None:
            raise ValueError("Master key SHA1 hash is required for decryption")

        blob_dpapick = dpapick3_blob.DPAPIBlob(self.raw_bytes)

        if not blob_dpapick.decrypt(masterkey.plaintext_key_sha1, entropy):
            raise BlobDecryptionError("Failed to decrypt blob with provided master key")

        if not blob_dpapick.cleartext:
            raise Exception("Decryption succeeded but no cleartext available")

        return blob_dpapick.cleartext


class BackupKeyRecoveryBlob(BaseModel):
    """Represents a BACKUPKEY_RECOVERY_BLOB structure.

    Used for domain backup key recovery operations in DPAPI.
    """

    model_config = {"frozen": True}

    raw_bytes: bytes

    version: int
    cb_encrypted_master_key: int
    cb_encrypted_payload: int
    guid_key: UUID
    encrypted_master_key: bytes
    encrypted_payload: bytes

    def __str__(self) -> str:
        """Return a string representation of the BackupKeyRecoveryBlob with all properties."""
        lines = [
            "BackupKeyRecoveryBlob()",
            f"  version: {self.version}",
            f"  cb_encrypted_master_key: {self.cb_encrypted_master_key}",
            f"  cb_encrypted_payload: {self.cb_encrypted_payload}",
            f"  guid_key: {self.guid_key}",
            f"  encrypted_master_key: {self.encrypted_master_key.hex()}",
            f"  encrypted_payload: {self.encrypted_payload.hex()}",
        ]
        return "\n".join(lines)

    @classmethod
    def from_file(cls, file_path: str | Path) -> BackupKeyRecoveryBlob:
        """Parse a BACKUPKEY_RECOVERY_BLOB from a file path.

        Args:
            file_path: Path to the BACKUPKEY_RECOVERY_BLOB file

        Returns:
            BackupKeyRecoveryBlob instance with parsed data

        Raises:
            ValueError: If format is invalid
            FileNotFoundError: If file doesn't exist
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Blob file not found: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        return cls.from_bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> BackupKeyRecoveryBlob:
        """Parse a BACKUPKEY_RECOVERY_BLOB from bytes.

        Args:
            data: Raw bytes containing the BACKUPKEY_RECOVERY_BLOB structure

        Returns:
            BackupKeyRecoveryBlob instance with parsed data

        Raises:
            ValueError: If the data format is not a valid BACKUPKEY_RECOVERY_BLOB structure
        """
        if len(data) < 28:  # Minimum size: 4 + 4 + 4 + 16
            raise ValueError(f"Data too short for BACKUPKEY_RECOVERY_BLOB: {len(data)} bytes")

        # Parse header: DWORD version, DWORD cbEncryptedMasterKey, DWORD cbEncryptedPayload
        blob_header = struct.unpack("<III", data[:12])
        version = blob_header[0]
        cb_encrypted_master_key = blob_header[1]
        cb_encrypted_payload = blob_header[2]

        # Validate version (typically 2 for BACKUPKEY_RECOVERY_BLOB)
        if version not in (1, 2, 3):
            raise ValueError(f"Unexpected BACKUPKEY_RECOVERY_BLOB version: {version}")

        # Validate data sizes are reasonable
        if cb_encrypted_master_key > len(data) or cb_encrypted_payload > len(data):
            raise ValueError(
                f"Invalid sizes: cb_encrypted_master_key={cb_encrypted_master_key}, "
                f"cb_encrypted_payload={cb_encrypted_payload}, data_len={len(data)}"
            )

        # Validate total size matches expected size
        expected_size = 28 + cb_encrypted_master_key + cb_encrypted_payload
        if len(data) < expected_size:
            raise ValueError(f"Data too short: expected {expected_size} bytes, got {len(data)} bytes")

        # Parse GUID (16 bytes starting at offset 12)
        guid_bytes = data[12:28]
        data1, data2, data3 = struct.unpack("<IHH", guid_bytes[:8])
        data4 = guid_bytes[8:16]
        guid_key = UUID(f"{data1:08x}-{data2:04x}-{data3:04x}-{data4[0]:02x}{data4[1]:02x}-{data4[2:].hex()}")

        # Extract encrypted master key and payload
        offset_emk = 28
        encrypted_master_key = data[offset_emk : offset_emk + cb_encrypted_master_key]
        offset_ep = offset_emk + cb_encrypted_master_key
        encrypted_payload = data[offset_ep : offset_ep + cb_encrypted_payload]

        # Validate we got the expected amount of data
        if len(encrypted_master_key) != cb_encrypted_master_key:
            raise ValueError(
                f"Encrypted master key size mismatch: expected {cb_encrypted_master_key}, "
                f"got {len(encrypted_master_key)}"
            )
        if len(encrypted_payload) != cb_encrypted_payload:
            raise ValueError(
                f"Encrypted payload size mismatch: expected {cb_encrypted_payload}, got {len(encrypted_payload)}"
            )

        return cls(
            raw_bytes=data,
            version=version,
            cb_encrypted_master_key=cb_encrypted_master_key,
            cb_encrypted_payload=cb_encrypted_payload,
            guid_key=guid_key,
            encrypted_master_key=encrypted_master_key,
            encrypted_payload=encrypted_payload,
        )


class MasterKeyFile(BaseModel):
    """Represents a DPAPI masterkey file structure.

    Based on the Windows MASTERKEY_STORED structure, this class can parse
    masterkey files from disk and extract the various key components.
    """

    version: int
    modified: bool
    file_path: None
    masterkey_guid: UUID
    policy: MasterKeyPolicy
    masterkey_type: MasterKeyType

    # Masterkey data (pbMK)
    master_key: bytes | None = None

    # Local key data (pbLK), a randomized key protected by a key derived from the user and system components of the DPAPI_SYSTEM secret
    local_key: bytes | None = None

    # Backup key data (pbBK), a structure protected by the Local Key that specifies the ID of the credential in CREDHIST needed to decrypt the masterkey.
    backup_key: bytes | None = None

    # Domain backup key ("DC recovery key" in MS parlance) protected masterkey data (pbBBK - backup backup key?).
    domain_backup_key: BackupKeyRecoveryBlob | None = None

    # Raw bytes of the entire master key file
    raw_bytes: bytes

    def __str__(self) -> str:
        """Return a string representation of the MasterKeyFile with all properties."""
        # Interpret policy flags
        policy_str = str(self.policy.name) if self.policy else "NONE"
        if self.policy and self.policy != MasterKeyPolicy.NONE:
            flags = []
            if self.policy.has_any(MasterKeyPolicy.LOCAL_BACKUP):
                flags.append("LOCAL_BACKUP")
            if self.policy.has_any(MasterKeyPolicy.NO_BACKUP):
                flags.append("NO_BACKUP")
            if self.policy.has_any(MasterKeyPolicy.DPAPI_OWF):
                flags.append("DPAPI_OWF")
            policy_str = " | ".join(flags) if flags else "NONE"

        lines = [
            "MasterKeyFile()",
            f"  version: {self.version}",
            f"  modified: {self.modified}",
            f"  file_path: {self.file_path}",
            f"  masterkey_guid: {self.masterkey_guid}",
            f"  policy: {self.policy} ({policy_str})\n",
            f"  masterkey_type: {self.masterkey_type.value}\n",
            f"master_key: {self.master_key.hex() if self.master_key else None}\n",
            f"local_key: {self.local_key.hex() if self.local_key else None}\n",
            f"backup_key: {self.backup_key.hex() if self.backup_key else None}\n",
            f"domain_backup_key: {self.domain_backup_key}",
        ]
        return "\n".join(lines)

    @classmethod
    def from_file(cls, file_path: str | Path, masterkey_type: MasterKeyType = MasterKeyType.UNKNOWN) -> MasterKeyFile:
        """Parse a masterkey file from disk.

        Args:
            file_path: Path to the masterkey file
            masterkey_type: Type of user account this masterkey belongs to (default: UNKNOWN)

        Returns:
            MasterKeyFile instance with parsed data

        Raises:
            ValueError: If file format is invalid
            FileNotFoundError: If file doesn't exist
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Masterkey file not found: {file_path}")

        with open(file_path, "rb") as f:
            data = f.read()

        return cls.from_bytes(data, masterkey_type=masterkey_type)

    @classmethod
    def from_bytes(cls, data: bytes, masterkey_type: MasterKeyType = MasterKeyType.UNKNOWN) -> MasterKeyFile:
        """Parse a masterkey from raw bytes.

        Args:
            data: Raw masterkey file bytes
            masterkey_type: Type of user account this masterkey belongs to (default: UNKNOWN)

        Returns:
            MasterKeyFile instance with parsed data

        Raises:
            ValueError: If file format is invalid
        """
        if len(data) < 44:  # Minimum size for MASTERKEY_STORED_ON_DISK header
            raise ValueError("File too small to contain valid masterkey data")

        # Parse the on-disk structure
        # struct format: DWORD dwVersion, BOOL fModified, DWORD szFilePath,
        #                WCHAR wszguidMasterKey[40], DWORD dwPolicy,
        #                DWORD cbMK, DWORD pbMK, DWORD cbLK, DWORD pbLK,
        #                DWORD cbBK, DWORD pbBK, DWORD cbBBK, DWORD pbBBK

        header_format = "<III80sIIIIIIIII"  # 80 bytes for WCHAR[40] (40 * 2)
        header_size = struct.calcsize(header_format)

        if len(data) < header_size:
            raise ValueError("File too small to contain complete header")

        header = struct.unpack(header_format, data[:header_size])

        version = header[0]
        if version != 2:
            raise ValueError(f"Unsupported masterkey file version: {version}")

        if header[1] not in (0, 1):
            raise ValueError(f"Invalid fModified value: {header[1]}")

        modified = bool(header[1])

        # Skip szFilePath (header[2]) - invalid on disk
        guid_bytes = header[3]
        policy = header[4]
        cb_mk = header[5]
        # Skip pbMK offset (header[6]) - invalid on disk
        cb_lk = header[7]
        # Skip pbLK offset (header[8]) - invalid on disk
        cb_bk = header[9]
        # Skip pbBK offset (header[10]) - invalid on disk
        cb_bbk = header[11]
        # Skip pbBBK offset (header[12]) - invalid on disk

        # Extract GUID string (null-terminated wide string) and convert to UUID
        guid_str = guid_bytes.decode("utf-16le").rstrip("\x00")
        guid = UUID(guid_str)

        # Validate total size
        total_key_size = cb_mk + cb_lk + cb_bk + cb_bbk
        if len(data) < header_size + total_key_size:
            raise ValueError("File size doesn't match expected key data size")

        # Extract key data sequentially after header
        offset = header_size

        master_key = None
        if cb_mk > 0:
            master_key = data[offset : offset + cb_mk]
            offset += cb_mk

        local_key = None
        if cb_lk > 0:
            local_key = data[offset : offset + cb_lk]
            offset += cb_lk

        backup_key = None
        if cb_bk > 0:
            backup_key = data[offset : offset + cb_bk]
            offset += cb_bk

        backup_dc_key = None
        if cb_bbk > 0:
            backup_dc_key_bytes = data[offset : offset + cb_bbk]
            backup_dc_key = BackupKeyRecoveryBlob.from_bytes(backup_dc_key_bytes)

        return cls(
            version=version,
            modified=modified,
            file_path=None,  # Invalid on disk, set to None
            masterkey_guid=guid,
            policy=MasterKeyPolicy(policy),
            masterkey_type=masterkey_type,
            master_key=master_key,
            local_key=local_key,
            backup_key=backup_key,
            domain_backup_key=backup_dc_key,
            raw_bytes=data,
        )

    def decrypt(self, backup_key: DomainBackupKey) -> MasterKey:
        """Decrypt this masterkey file using a domain backup key.

        Args:
            backup_key: The domain backup key to use for decryption

        Returns:
            MasterKey instance with decrypted key data

        Raises:
            ValueError: If masterkey file has no domain backup key
            InvalidBackupKeyError: If domain backup key is invalid or malformed
            MasterKeyDecryptionError: If decryption fails
        """
        if not self.domain_backup_key:
            raise ValueError("Masterkey file contains no domain backup key data")

        try:
            # Extract the private key from the backup key data
            key = PRIVATE_KEY_BLOB(backup_key.key_data[len(PVK_FILE_HDR()) :])
            private = privatekeyblob_to_pkcs1(key)
            cipher = PKCS1_v1_5.new(private)
        except Exception as e:
            raise InvalidBackupKeyError(f"Invalid domain backup key: {e}") from e

        # Decrypt the masterkey. Encrypted masterkey is in reverse byte order (per Impacket implementation)
        decrypted_key = cipher.decrypt(self.domain_backup_key.encrypted_master_key[::-1], None)

        if not decrypted_key:
            raise MasterKeyDecryptionError("Failed to decrypt masterkey with backup key")

        domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decrypted_key)
        buffer = domain_master_key["buffer"]

        # If it's a version 3 masterkey, skip the first 8 bytes (structure is different)
        if len(decrypted_key) == 128:
            key_offset = 8
        elif len(decrypted_key) == 104:
            key_offset = 0
        else:
            raise MasterKeyDecryptionError(
                f"Unexpected decrypted key length: {len(decrypted_key)}. Decrypted key: {decrypted_key.hex()}"
            )

        plaintext_key = buffer[key_offset : key_offset + domain_master_key["cbMasterKey"]]
        plaintext_key_sha1 = SHA1.new(plaintext_key).digest()

        return MasterKey(
            guid=self.masterkey_guid,
            masterkey_type=self.masterkey_type,
            encrypted_key_usercred=self.master_key,
            encrypted_key_backup=self.domain_backup_key.raw_bytes,
            plaintext_key=plaintext_key,
            plaintext_key_sha1=plaintext_key_sha1,
            backup_key_guid=backup_key.guid,
        )
