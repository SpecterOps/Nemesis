"""DPAPI cryptographic operations."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from Crypto.Hash import HMAC, MD4, SHA1, SHA256
from Crypto.Protocol.KDF import PBKDF2
from pydantic import BaseModel, field_validator

from .dpapi_blob import DPAPI_BLOB
from .exceptions import DpapiCryptoError

if TYPE_CHECKING:
    from .types import Sid


class InvalidBlobDataError(DpapiCryptoError):
    """Raised when DPAPI blob data is invalid or malformed."""

    pass


class BlobDecryptionError(DpapiCryptoError):
    """Raised when DPAPI blob decryption fails."""

    pass


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
    derived_key = PBKDF2(
        ntlm_hash, user_sid_bytes, dkLen=32, count=10000, hmac_hash_module=SHA256
    )  # type: ignore
    derived_key = PBKDF2(
        derived_key, user_sid_bytes, dkLen=16, count=1, hmac_hash_module=SHA256
    )  # type: ignore
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
    def from_password(
        cls, password: str, hash_type: CredKeyHashType, user_sid: Sid | None = None
    ) -> CredKey:
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
    def from_ntlm(
        cls, ntlm_hash: bytes, hash_type: CredKeyHashType, user_sid: Sid | None = None
    ) -> CredKey:
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


class DpapiCrypto:
    """DPAPI cryptographic operations handler."""

    @staticmethod
    def decrypt_blob(
        blob_data: bytes, masterkey: bytes, entropy: bytes | None = None
    ) -> bytes:
        """Decrypt a DPAPI blob using the provided masterkey SHA1.

        Args:
            blob_data: The encrypted DPAPI blob's bytes
            masterkey: Bytes of the plaintext masterkey
            entropy: Optional entropy data used in blob encryption

        Returns:
            Decrypted blob data

        Raises:
            InvalidBlobDataError: If blob data is invalid or malformed
            BlobDecryptionError: If decryption fails
        """
        try:
            dpapi_blob = DPAPI_BLOB(blob_data)
        except Exception as e:
            raise InvalidBlobDataError(f"Invalid DPAPI blob data: {e}") from e

        decrypted_data = dpapi_blob.decrypt(masterkey)

        if not decrypted_data:
            raise BlobDecryptionError("Failed to decrypt DPAPI blob")

        return decrypted_data
