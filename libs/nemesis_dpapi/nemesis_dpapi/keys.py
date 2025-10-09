"""DPAPI cryptographic operations."""

from __future__ import annotations

import struct
from enum import Enum
from typing import TYPE_CHECKING
from uuid import UUID  # noqa: TC003 - need for pydantic

from Crypto.Hash import HMAC, MD4, SHA1, SHA256
from Crypto.Protocol.KDF import PBKDF2
from impacket.dpapi import PRIVATE_KEY_BLOB
from pydantic import BaseModel, ConfigDict, field_serializer, field_validator

if TYPE_CHECKING:
    from .types import Sid


# PVK file format constants
PVK_MAGIC = 0xB0B5F11E
PVK_FILE_VERSION_0 = 0
PVK_NO_ENCRYPT = 0
MAX_PVK_FILE_LEN = 4096


class PvkFileHeader(BaseModel):
    """PVK file header structure.

    Based on the Microsoft PVK file format:
    typedef struct _FILE_HDR {
        DWORD dwMagic;
        DWORD dwVersion;
        DWORD dwKeySpec;
        DWORD dwEncryptType;
        DWORD cbEncryptData;
        DWORD cbPvk;
    } FILE_HDR, *PFILE_HDR;
    """

    model_config = ConfigDict(frozen=True)

    magic: int  # Should be PVK_MAGIC (0xb0b5f11e)
    version: int  # Should be PVK_FILE_VERSION_0 (0)
    key_spec: int  # Key specification
    encrypt_type: int  # Encryption type (PVK_NO_ENCRYPT = 0)
    encrypt_data_size: int  # Size of encrypted data
    pvk_size: int  # Size of private key data

    encrypted_data: bytes
    private_key: bytes

    @classmethod
    def parse(cls, data: bytes) -> PvkFileHeader:
        """Parse PVK file header from bytes.

        Args:
            data: Raw bytes containing the PVK file header and key data

        Returns:
            Parsed PvkFileHeader instance

        Raises:
            ValueError: If data is too short or header is invalid
        """
        if len(data) < 24:
            raise ValueError(f"Data too short for PVK header: {len(data)} bytes, need at least 24")

        magic, version, key_spec, encrypt_type, encrypt_data_size, pvk_size = struct.unpack("<6I", data[:24])

        if magic != PVK_MAGIC:
            raise ValueError(f"Invalid PVK magic: 0x{magic:08x}, expected 0x{PVK_MAGIC:08x}")

        if version != PVK_FILE_VERSION_0:
            raise ValueError(f"Invalid PVK version: {version}, expected {PVK_FILE_VERSION_0}")

        if encrypt_data_size > MAX_PVK_FILE_LEN:
            raise ValueError(f"Encrypted data size too large: {encrypt_data_size}, max {MAX_PVK_FILE_LEN}")

        if pvk_size == 0 or pvk_size > MAX_PVK_FILE_LEN:
            raise ValueError(f"Invalid PVK size: {pvk_size}, must be 1-{MAX_PVK_FILE_LEN}")

        # Parse encrypted data (if present) and private key
        offset = 24

        # Extract encrypted data if present
        if encrypt_data_size > 0:
            if len(data) < offset + encrypt_data_size:
                raise ValueError(f"Data too short for encrypted data: need {offset + encrypt_data_size} bytes")
            encrypted_data = data[offset:offset + encrypt_data_size]
            offset += encrypt_data_size
        else:
            encrypted_data = b""

        # Extract private key data
        if len(data) < offset + pvk_size:
            raise ValueError(f"Data too short for private key: need {offset + pvk_size} bytes")
        private_key = data[offset:offset + pvk_size]

        return cls(
            magic=magic,
            version=version,
            key_spec=key_spec,
            encrypt_type=encrypt_type,
            encrypt_data_size=encrypt_data_size,
            pvk_size=pvk_size,
            encrypted_data=encrypted_data,
            private_key=private_key,
        )


class Password(BaseModel):
    """Password credential."""

    value: str

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        if not v:
            raise ValueError("Password value cannot be empty")
        return v


class NtlmHash(BaseModel):
    """NTLM hash credential."""

    value: bytes

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: bytes) -> bytes:
        if not v:
            raise ValueError("NTLM hash value cannot be empty")
        if len(v) != 16:
            raise ValueError("NTLM hash must be exactly 16 bytes")
        return v

    @classmethod
    def from_hexstring(cls, hex_string: str) -> NtlmHash:
        """Create NtlmHash from hex string."""
        try:
            return cls(value=bytes.fromhex(hex_string))
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e


class Sha1Hash(BaseModel):
    """SHA1 hash credential."""

    value: bytes

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: bytes) -> bytes:
        if not v:
            raise ValueError("SHA1 hash value cannot be empty")
        if len(v) != 20:
            raise ValueError("SHA1 hash must be exactly 20 bytes")
        return v

    @classmethod
    def from_hex(cls, hex_string: str) -> Sha1Hash:
        """Create Sha1Hash from hex string."""
        try:
            return cls(value=bytes.fromhex(hex_string))
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e


class Pbkdf2Hash(BaseModel):
    """PBKDF2 hash credential."""

    value: bytes

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: bytes) -> bytes:
        if not v:
            raise ValueError("PBKDF2 hash value cannot be empty")
        if len(v) != 16:
            raise ValueError("PBKDF2 hash must be exactly 16 bytes")
        return v

    @classmethod
    def from_hex(cls, hex_string: str) -> Pbkdf2Hash:
        """Create Pbkdf2Hash from hex string."""
        try:
            return cls(value=bytes.fromhex(hex_string))
        except ValueError as e:
            raise ValueError(f"Invalid hex string: {e}") from e


def _derive_secure_cred_key(ntlm_hash: bytes, user_sid_bytes: bytes) -> bytes:
    """Compute PBKDF2 hash using two-step derivation process."""
    derived_key = PBKDF2(ntlm_hash, user_sid_bytes, dkLen=32, count=10000, hmac_hash_module=SHA256)  # type: ignore
    derived_key = PBKDF2(derived_key, user_sid_bytes, dkLen=16, count=1, hmac_hash_module=SHA256)  # type: ignore
    return derived_key


class CredKeyHashType(Enum):
    """Type of one-way function (OWF) hashes used in credential key derivation."""

    MD4 = "md4"  # MD4 hash (16 bytes)
    NTLM = "md4"  # Alias for MD4
    SHA1 = "sha1"  # SHA1 hash (20 bytes)
    PBKDF2 = "pbkdf2"  # "Secure" Cred Key, 16 bytes derived from PBKDF2
    SECURE_CRED_KEY = "pbkdf2"  # Alias for PBKDF2


class CredKey(BaseModel):
    """Credential key derived from OWF hash."""

    key: NtlmHash | Sha1Hash | Pbkdf2Hash

    @property
    def owf(self) -> CredKeyHashType:
        """Get the OWF type inferred from the hash type."""
        if isinstance(self.key, NtlmHash):
            return CredKeyHashType.NTLM
        elif isinstance(self.key, Sha1Hash):
            return CredKeyHashType.SHA1
        elif isinstance(self.key, Pbkdf2Hash):
            return CredKeyHashType.PBKDF2
        else:
            raise ValueError(f"Cannot infer OWF type from key type: {type(self.key)}")

    @classmethod
    def from_password(cls, password: str, hash_type: CredKeyHashType, user_sid: Sid | None = None) -> CredKey:
        """Create CredKey from password by calculating the specified hash type.

        Args:
            password: The user's password
            hash_type: The type of hash to compute (NTLM, SHA1, PBKDF2)
            user_sid: (Optional) The user's SID. Only required for PBKDF2 derivation.

        Returns:
            CredKey object with the computed hash

        Raises:
            ValueError: If parameters are invalid or unsupported hash type

        Note:
            Derived from SharpDPAPI's CalculateKeys function: https://github.com/GhostPack/SharpDPAPI/blob/master/SharpDPAPI/lib/Dpapi.cs#L1755
        """

        if hash_type in (CredKeyHashType.MD4, CredKeyHashType.NTLM):
            ntlm_hash = MD4.new(password.encode("utf-16le")).digest()
            return cls(key=NtlmHash(value=ntlm_hash))
        elif hash_type == CredKeyHashType.SHA1:
            sha1_hash = SHA1.new(password.encode("utf-16le")).digest()
            return cls(key=Sha1Hash(value=sha1_hash))
        elif hash_type == CredKeyHashType.PBKDF2:
            if user_sid is None:
                raise ValueError("user_sid parameter is required when using PBKDF2")

            user_sid_bytes = user_sid.encode("utf-16le")
            ntlm_hash = MD4.new(password.encode("utf-16le")).digest()

            derived_key = _derive_secure_cred_key(ntlm_hash, user_sid_bytes)

            return cls(key=Pbkdf2Hash(value=derived_key))
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")

    @classmethod
    def from_ntlm(cls, ntlm_hash: bytes, hash_type: CredKeyHashType, user_sid: Sid | None = None) -> CredKey:
        """Create CredKey from NTLM hash."""

        if hash_type in (CredKeyHashType.MD4, CredKeyHashType.NTLM):
            return cls(key=NtlmHash(value=ntlm_hash))
        elif hash_type == CredKeyHashType.PBKDF2:
            if user_sid is None:
                raise ValueError("user_sid parameter is required when using PBKDF2")

            user_sid_bytes = user_sid.encode("utf-16le")
            derived_key = _derive_secure_cred_key(ntlm_hash, user_sid_bytes)

            return cls(key=Pbkdf2Hash(value=derived_key))
        else:
            raise ValueError(f"Cannot derive {hash_type} from NTLM hash")

    @classmethod
    def from_sha1(cls, sha1_hash: bytes) -> CredKey:
        """Create CredKey from SHA1 hash."""
        return cls(key=Sha1Hash(value=sha1_hash))

    @classmethod
    def from_pbkdf2(cls, pbkdf2_hash: bytes) -> CredKey:
        """Create CredKey from PBKDF2 hash."""
        return cls(key=Pbkdf2Hash(value=pbkdf2_hash))


class MasterKeyEncryptionKey(BaseModel):
    """Symmetric encryption key derived from credential key."""

    key: Sha1Hash

    @staticmethod
    def _derive_mk_key(pwdhash: bytes, user_sid: Sid, digest: str = "sha1") -> bytes:
        """Internal use. Computes the DPAPI symmetric key from a hash derived from a user's password."""
        # Map digest names to pycryptodome hash modules
        digest_map = {
            "sha1": SHA1,
            "sha256": SHA256,
            "md4": MD4,
        }

        if digest not in digest_map:
            raise ValueError(f"Unsupported digest algorithm: {digest}")

        user_sid_bytes = user_sid.encode("utf-16le") + b"\0\0"

        return HMAC.new(pwdhash, user_sid_bytes, digestmod=digest_map[digest]).digest()

    @classmethod
    def from_cred_key(cls, cred_key: CredKey, user_sid: Sid) -> MasterKeyEncryptionKey:
        """Generate symmetric key from credential key using derivation algorithm.

        Args:
            cred_key: The credential key containing hash
            user_sid: The user SID (used in the key derivation)
        """
        if cred_key.owf in (CredKeyHashType.MD4, CredKeyHashType.NTLM):
            if not isinstance(cred_key.key, NtlmHash):
                raise ValueError("Expected NtlmHash for MD4/NTLM key type")
            key = cls._derive_mk_key(cred_key.key.value, user_sid, digest="sha1")
        elif cred_key.owf == CredKeyHashType.SHA1:
            if not isinstance(cred_key.key, Sha1Hash):
                raise ValueError("Expected Sha1Hash for SHA1 key type")
            key = cls._derive_mk_key(cred_key.key.value, user_sid, digest="sha1")
        elif cred_key.owf == CredKeyHashType.PBKDF2:
            if not isinstance(cred_key.key, Pbkdf2Hash):
                raise ValueError("Expected Pbkdf2Hash for PBKDF2 key type")

            key = cls._derive_mk_key(cred_key.key.value, user_sid, digest="sha1")
        else:
            raise ValueError(f"Invalid hash_type: {cred_key.owf}")

        return cls(key=Sha1Hash(value=key))

    @classmethod
    def from_dpapi_system_cred(cls, dpapi_system_key: bytes) -> MasterKeyEncryptionKey:
        """Generate symmetric key from DPAPI_SYSTEM credential.

        Args:
            dpapi_system_key: The DPAPI_SYSTEM key bytes
        """
        return cls(key=Sha1Hash(value=dpapi_system_key))


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

        # Check minimum size - PVK header is 24 bytes
        pvk_header_size = 24
        if len(v) < pvk_header_size:
            raise ValueError(
                f"key_data too short: {len(v)} bytes, minimum {pvk_header_size} bytes required for PVK header"
            )

        try:
            # Validate PVK header and full structure can be parsed
            # This validates magic number, version, sizes, and private key blob
            header = PvkFileHeader.parse(v)
        except Exception as e:
            raise ValueError(f"Invalid PVK file header: {e}") from e

        try:
            # Validate PRIVATE_KEY_BLOB can be parsed from the private key data
            PRIVATE_KEY_BLOB(header.private_key)
        except Exception as e:
            raise ValueError(f"Invalid private key blob: {e}") from e

        return v


class DpapiSystemCredential(BaseModel):
    """Represents the DPAPI_SYSTEM LSA secret key for decrypting machine-protected masterkeys."""

    model_config = ConfigDict(frozen=True)

    user_key: bytes
    machine_key: bytes

    @field_validator("user_key", "machine_key", mode="before")
    @classmethod
    def deserialize_hex_to_bytes(cls, v: bytes | str) -> bytes:
        """Deserialize hex strings back to bytes."""
        if isinstance(v, str):
            return bytes.fromhex(v)
        return v

    @field_serializer("user_key", "machine_key")
    def serialize_bytes_as_hex(self, value: bytes) -> str:
        """Serialize bytes fields as hex strings for JSON serialization."""
        return value.hex()

    def model_dump(self, **kwargs):
        """Override to serialize bytes as hex strings."""
        data = super().model_dump(**kwargs)
        data["user_key"] = self.user_key.hex()
        data["machine_key"] = self.machine_key.hex()
        return data

    @classmethod
    def from_bytes(cls, dpapi_system_data: bytes | str) -> DpapiSystemCredential:
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
    def from_lsa_secret(cls, lsa_secret_bytes: bytes | str) -> DpapiSystemCredential:
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
