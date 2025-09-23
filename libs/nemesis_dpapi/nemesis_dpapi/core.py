"""Core data types used in the DPAPI library"""

import json
import struct
from enum import IntFlag
from pathlib import Path
from uuid import UUID

from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.Hash import SHA1
from impacket.dpapi import DPAPI_DOMAIN_RSA_MASTER_KEY, PRIVATE_KEY_BLOB, PVK_FILE_HDR, privatekeyblob_to_pkcs1
from impacket.dpapi import DomainKey as ImpacketDomainKey
from impacket.dpapi import MasterKey as ImpacketMasterKey
from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, field_validator

from .crypto import MasterKeyEncryptionKey
from .dpapi_blob import DPAPI_BLOB
from .exceptions import InvalidBackupKeyError, MasterKeyDecryptionError

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


class MasterKeyPolicy(IntFlag):
    """Policy bits for DPAPI masterkey."""

    NONE = 0x0  # No special policy
    LOCAL_BACKUP = 0x1  # Policy bit for local only (no DC) backup
    NO_BACKUP = 0x2  # Policy bit for NO backup (Win95)
    DPAPI_OWF = 0x4  # Use the DPAPI One way function of the password (SHA_1(pw))


class MasterKey(BaseModel):
    """Represents a DPAPI masterkey.

    Attributes:
        guid: Unique identifier for this masterkey.
        encrypted_key_user: Masterkey encrypted with the user's password-derived key.
        encrypted_key_backup: Masterkey encrypted with the domain backup key.
        backup_key_guid: GUID of the domain backup key used to encrypt this masterkey.
        plaintext_key: Decrypted masterkey data.
        plaintext_key_sha1: SHA1 hash of the plaintext masterkey. AKA the Master Key (MK) Encryption Key.
    """

    guid: UUID
    encrypted_key_usercred: bytes | None = None
    encrypted_key_backup: bytes | None = None
    plaintext_key: bytes | None = None
    plaintext_key_sha1: bytes | None = None
    backup_key_guid: UUID | None = None

    @property
    def is_decrypted(self) -> bool:
        """Check if masterkey has been decrypted."""
        return self.plaintext_key is not None

    def decrypt(self, master_key_encryption_key: MasterKeyEncryptionKey) -> "MasterKey":
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
    def parse(cls, data_or_path: bytes | str | Path) -> "Blob":
        """Parse a DPAPI blob from bytes or file path.

        Args:
            data_or_path: Either raw bytes or path to blob file

        Returns:
            DpapiBlob instance with parsed data

        Raises:
            ValueError: If blob format is invalid
            FileNotFoundError: If file doesn't exist
        """

        def _parse_guid(data: bytes) -> UUID:
            # '<' = little-endian for first 3 fields, '>' = big-endian for last field
            data1, data2, data3 = struct.unpack("<IHH", data[:8])
            data4 = data[8:16]  # Keep as bytes (big-endian)

            return UUID(f"{data1:08x}-{data2:04x}-{data3:04x}-{data4[0]:02x}{data4[1]:02x}-{data4[2:].hex()}")

        if isinstance(data_or_path, (str, Path)):
            file_path = Path(data_or_path)
            if not file_path.exists():
                raise FileNotFoundError(f"Blob file not found: {file_path}")
            with open(file_path, "rb") as f:
                data = f.read()
        else:
            data = data_or_path

        try:
            dpapi_blob = DPAPI_BLOB(data)
        except Exception as e:
            raise ValueError(f"Failed to parse DPAPI blob: {e}") from e

        # Convert impacket DPAPI_BLOB fields to our Blob class fields
        # Parse Windows GUIDs from bytes to UUID
        masterkey_guid_bytes = dpapi_blob["GuidMasterKey"]
        masterkey_guid = _parse_guid(masterkey_guid_bytes)

        provider_guid_bytes = dpapi_blob["GuidCredential"]
        provider_guid = _parse_guid(provider_guid_bytes)

        # Validate versions are both 1
        if dpapi_blob["Version"] != 1:
            raise ValueError(f"Invalid outer version: {dpapi_blob['Version']}")
        if dpapi_blob["MasterKeyVersion"] != 1:
            raise ValueError(f"Invalid master key version: {dpapi_blob['MasterKeyVersion']}")

        # Validate the provider GUID is DF9D8CD0-1501-11D1-8C7A-00C04FC297EB
        if provider_guid != DEFAULT_BLOB_PROVIDER_GUID:
            raise ValueError(f"Invalid provider GUID: {provider_guid}")

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

    # Masterkey data (pbMK)
    master_key: bytes | None = None

    # Local key data (pbLK), a randomized key protected by a key derived from the user and system components of the DPAPI_SYSTEM secret
    local_key: bytes | None = None

    # Backup key data (pbBK), a structure protected by the Local Key that specifies the ID of the credential in CREDHIST needed to decrypt the masterkey.
    backup_key: bytes | None = None

    # Domain backup key ("DC recovery key" in MS parlance) protected masterkey data (pbBBK - backup backup key?).
    domain_backup_key: bytes | None = None

    # Raw bytes of the entire master key file
    raw_bytes: bytes | None = None

    @classmethod
    def parse(cls, file_path: str | Path) -> "MasterKeyFile":
        """Parse a masterkey file from disk.

        Args:
            file_path: Path to the masterkey file

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
            backup_dc_key = data[offset : offset + cb_bbk]

        return cls(
            version=version,
            modified=modified,
            file_path=None,  # Invalid on disk, set to None
            masterkey_guid=guid,
            policy=MasterKeyPolicy(policy),
            master_key=master_key,
            local_key=local_key,
            backup_key=backup_key,
            domain_backup_key=backup_dc_key,
            raw_bytes=data,
        )


class DomainBackupKey(BaseModel):
    """Represents a domain backup key for decrypting masterkeys."""

    model_config = {"frozen": True}

    guid: UUID
    key_data: bytes
    domain_controller: str | None = None

    @field_validator("key_data")
    @classmethod
    def validate_key_data(cls, v: bytes) -> bytes:
        """Validate that key_data contains a correctly formatted domain backup key.

        A valid domain backup key should:
        1. Be at least large enough to contain a PVK file header
        2. Have a valid PVK file header structure
        3. Have a valid PRIVATE_KEY_BLOB structure following the header

        Args:
            v: The key_data bytes to validate

        Returns:
            The validated key_data bytes

        Raises:
            ValueError: If the key_data is not a valid domain backup key
        """
        if not isinstance(v, bytes):
            raise ValueError("key_data must be bytes")

        # Check minimum size - PVK header is at least 20 bytes
        pvk_header_size = len(PVK_FILE_HDR())
        if len(v) < pvk_header_size:
            raise ValueError(f"key_data too short: {len(v)} bytes, minimum {pvk_header_size} bytes required for PVK header")

        try:
            # Validate PVK header can be parsed
            PVK_FILE_HDR(v[:pvk_header_size])
        except Exception as e:
            raise ValueError(f"Invalid PVK file header: {e}") from e

        try:
            # Validate PRIVATE_KEY_BLOB can be parsed from the remaining data
            private_key_data = v[pvk_header_size:]
            if len(private_key_data) == 0:
                raise ValueError("No private key data found after PVK header")
            PRIVATE_KEY_BLOB(private_key_data)
        except Exception as e:
            raise ValueError(f"Invalid private key blob: {e}") from e

        return v

    def decrypt_masterkey_file(self, masterkey_file: MasterKeyFile) -> MasterKey:
        """Decrypt a masterkey file using this domain backup key.

        Args:
            masterkey_file: The masterkey file to decrypt

        Returns:
            MasterKey instance with decrypted key data

        Raises:
            MasterKeyDecryptionError: If masterkey file has no domain backup key or decryption fails
            InvalidBackupKeyError: If domain backup key is invalid or malformed
        """
        if not masterkey_file.domain_backup_key:
            raise ValueError("Masterkey file contains no domain backup key data")

        try:
            domain_key = ImpacketDomainKey(masterkey_file.domain_backup_key)
        except Exception as e:
            raise ValueError(f"Failed to parse domain backup key data from master key file: {e}") from e

        try:
            # Extract the private key from the backup key data
            key = PRIVATE_KEY_BLOB(self.key_data[len(PVK_FILE_HDR()) :])
            private = privatekeyblob_to_pkcs1(key)
            cipher = PKCS1_v1_5.new(private)
        except Exception as e:
            raise InvalidBackupKeyError(f"Invalid domain backup key: {e}") from e

        # Decrypt the masterkey (reverse byte order as per Impacket implementation)
        decrypted_key = cipher.decrypt(domain_key["SecretData"][::-1], None)

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
            guid=masterkey_file.masterkey_guid,
            encrypted_key_usercred=masterkey_file.master_key,
            encrypted_key_backup=masterkey_file.domain_backup_key,
            plaintext_key=plaintext_key,
            plaintext_key_sha1=plaintext_key_sha1,
            backup_key_guid=self.guid,
        )


class DpapiSystemCredential(BaseModel):
    """Represents the DPAPI_SYSTEM LSA secret key for decrypting machine-protected masterkeys."""

    model_config = ConfigDict(frozen=True)

    user_key: bytes
    machine_key: bytes

    @classmethod
    def from_bytes(cls, dpapi_system_data: bytes | str) -> "DpapiSystemCredential":
        """Create a DpapiSystemCredential from bytes.

        Args:
            dpapi_system_data (bytes | str): 40-byte DPAPI_SYSTEM LSA secret
                (as raw bytes or hex string).

        Returns:
            DpapiSystemKey: A new instance created from the given secret.

        Raises:
            ValueError: If dpapi_system_data is not exactly 40 bytes or
                80 hex characters.

        Note:
            For creating a DpapiSystemCredential from the bytes of the
            DPAPI_SYSTEM LSA secret, use the from_lsa_secret method instead.
        """

        if isinstance(dpapi_system_data, str):
            try:
                dpapi_system_bytes = bytes.fromhex(dpapi_system_data)
            except ValueError as e:
                raise ValueError(f"Invalid hex string: {e}") from e
        else:
            dpapi_system_bytes = dpapi_system_data

        if len(dpapi_system_bytes) != 40:
            raise ValueError(f"DPAPI_SYSTEM must be exactly 40 bytes, got {len(dpapi_system_bytes)}")

        # Split into machine (first 20 bytes) and user (last 20 bytes) components
        machine_key_bytes = dpapi_system_bytes[:20]
        user_key_bytes = dpapi_system_bytes[20:]

        return cls(user_key=user_key_bytes, machine_key=machine_key_bytes)

    @classmethod
    def from_lsa_secret(cls, lsa_secret_bytes: bytes | str) -> "DpapiSystemCredential":
        """Create DpapiSystemSecret from the DPAPI_SYSTEM LSA secret.

        Args:
            lsa_secret_bytes: LSA secret structure containing version and keys (as bytes or hex string)

        Returns:
            DpapiSystemSecret instance

        Raises:
            ValueError: If structure is invalid or missing required data
        """
        # Convert hex string to bytes if needed
        if isinstance(lsa_secret_bytes, str):
            try:
                lsa_secret_data = bytes.fromhex(lsa_secret_bytes)
            except ValueError as e:
                raise ValueError(f"Invalid hex string: {e}") from e
        else:
            lsa_secret_data = lsa_secret_bytes

        if len(lsa_secret_data) != 44:  # 4 + 20 + 20 = minimum structure size
            raise ValueError(f"Incorrect LSA secret size, expected at least 44 bytes, got {len(lsa_secret_data)}")

        try:
            # Parse structure: Version (4 bytes), MachineKey (20 bytes), UserKey (20 bytes)
            version, machine_key, user_key = struct.unpack("<L20s20s", lsa_secret_data[:44])
        except struct.error as e:
            raise ValueError(f"Failed to parse LSA secret structure: {e}") from e

        if version != 1:
            raise ValueError(f"Unexpected LSA secret version: {version}, expected 1")

        return cls(user_key=user_key, machine_key=machine_key)
