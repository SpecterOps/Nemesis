"""DPAPI credential models for API requests."""

import re
from typing import Annotated, Literal
from uuid import UUID

from common.logger import get_logger
from nemesis_dpapi.types import Sid  # pyright: ignore[reportMissingImports]
from pydantic import BaseModel, Discriminator, Field, Tag, field_serializer, field_validator

logger = get_logger(__name__)


class PasswordCredentialKey(BaseModel):
    """Use a plaintext password to derive a DPAPI credential key."""

    model_config = {"frozen": True, "extra": "forbid"}

    type: Literal["password"]
    value: str  # Plain text password
    user_sid: Sid  # Required for to derive MK encryption keys


class NtlmHashCredentialKey(BaseModel):
    """Use an NTLM hash to derive a DPAPI credential key."""

    model_config = {"frozen": True, "extra": "forbid"}

    type: Literal["cred_key_ntlm"]
    value: str  # Hex string representation of NTLM hash (16 bytes)
    user_sid: Sid  # Required for to derive MK encryption keys

    @field_validator("value")
    @classmethod
    def validate_ntlm_hash_length(cls, v):
        """Validate that value is exactly 32 hex characters (16 bytes)."""
        if len(v) != 32:
            raise ValueError(f"NTLM hash value must be exactly 32 hex characters (16 bytes), got {len(v)} characters")
        if not re.match(r"^[0-9a-fA-F]+$", v):
            raise ValueError("NTLM hash value must contain only hex characters (0-9, a-f, A-F)")
        return v


class Sha1CredentialKey(BaseModel):
    """Use a SHA1 hash to derive a DPAPI credential key."""

    model_config = {"frozen": True, "extra": "forbid"}

    type: Literal["cred_key_sha1"]
    value: str  # Hex string representation of credential key (20 bytes)
    user_sid: Sid  # Required for to derive MK encryption keys

    @field_validator("value")
    @classmethod
    def validate_cred_key_length(cls, v):
        """Validate that value is either 40 hex characters (20 bytes)."""
        if len(v) != 40:
            raise ValueError(f"SHA1 credential key value must be 40 hex characters (20 bytes), got {len(v)} characters")
        if not re.match(r"^[0-9a-fA-F]+$", v):
            raise ValueError("SHA1 Credential key value must contain only hex characters (0-9, a-f, A-F)")
        return v


class Pbkdf2StrongCredentialKey(BaseModel):
    """Credential key object."""

    model_config = {"frozen": True, "extra": "forbid"}

    type: Literal["cred_key_pbkdf2"]
    value: str  # Hex string representation of credential key (16 bytes)
    user_sid: Sid  # Required to derive MK encryption keys

    @field_validator("value")
    @classmethod
    def validate_cred_key_length(cls, v):
        """Validate that value is either 32 hex characters (16 bytes)."""
        if len(v) != 32:
            raise ValueError(
                f"Secure credential key (PBKDF2) value must be exactly 32 hex characters (16 bytes), got {len(v)} characters"
            )
        if not re.match(r"^[0-9a-fA-F]+$", v):
            raise ValueError("Secure credential key (PBKDF2) value must contain only hex characters (0-9, a-f, A-F)")
        return v


class DomainBackupKeyCredential(BaseModel):
    """Domain backup key credential (PVK format)."""

    model_config = {"frozen": True, "extra": "forbid"}

    type: Literal["domain_backup_key"]
    value: str  # Base64 encoded PVK data
    guid: str  # Domain backup key GUID (UUID format)
    domain_controller: str | None = None  # Optional domain controller

    @field_validator("guid")
    @classmethod
    def validate_guid_format(cls, v):
        """Validate that guid is a valid UUID format."""
        try:
            UUID(v)  # This will raise ValueError if not valid UUID format
            return v
        except ValueError as e:
            raise ValueError(f"guid must be a valid UUID format, got: {v}") from e


class MasterKeyGuidPair(BaseModel):
    """Strongly typed master key data."""

    model_config = {"frozen": True, "extra": "forbid"}

    guid: UUID = Field(description="Master key GUID")
    key_hex: str = Field(description="Hex-encoded master key bytes", pattern=r"^[0-9a-fA-F]+$")

    @field_serializer("guid")
    def serialize_guid(self, value: UUID) -> str:
        return str(value)


class MasterKeyGuidPairList(BaseModel):
    """Decrypted master key/GUID pairs."""

    model_config = {"frozen": True, "extra": "forbid"}

    type: Literal["master_key_guid_pair"]
    value: list[MasterKeyGuidPair]


class DpapiSystemCredentialRequest(BaseModel):
    """DPAPI_SYSTEM LSA Secret credential sent in an API request."""

    model_config = {"frozen": True, "extra": "forbid"}

    type: Literal["dpapi_system"]
    value: str = Field(
        description="Hex-encoded DPAPI_SYSTEM LSA secret (40 bytes)",
        pattern=r"^[0-9a-fA-F]{80}$",
    )

    @field_validator("value")
    @classmethod
    def validate_hex_length(cls, v):
        """Validate that value is exactly 80 hex characters (40 bytes)."""
        if len(v) != 80:
            raise ValueError(
                f"DPAPI_SYSTEM value must be exactly 80 hex characters (40 bytes), got {len(v)} characters"
            )
        if not re.match(r"^[0-9a-fA-F]+$", v):
            raise ValueError("DPAPI_SYSTEM value must contain only hex characters (0-9, a-f, A-F)")
        return v


class ChromiumAppBoundKeyCredential(BaseModel):
    """Chromium App-Bound-Encryption key credential."""

    model_config = {"frozen": True, "extra": "forbid"}

    type: Literal["chromium_app_bound_key"]
    value: str  # Hex string or Python escaped format (\\x5f\\x1a...)
    source: str  # Required source identifier
    browser: Literal["chrome", "edge", "brave", "opera"] = "chrome"  # Browser type
    username: str = "UNKNOWN"  # Optional username, defaults to UNKNOWN

    @field_validator("value")
    @classmethod
    def validate_key_format(cls, v):
        """Validate that value is 32 bytes in either hex or escaped format."""
        # Try to parse as Python escaped format first (e.g., \x5f\x1a...)
        if "\\x" in v:
            try:
                # Remove any quotes and decode the escaped string
                cleaned = v.strip().strip('"').strip("'")
                # Convert escaped format to bytes
                key_bytes = cleaned.encode().decode("unicode_escape").encode("latin1")
                if len(key_bytes) != 32:
                    raise ValueError(
                        f"Chromium App-Bound key must be exactly 32 bytes, got {len(key_bytes)} bytes from escaped format"
                    )
                return v
            except Exception as e:
                raise ValueError(f"Invalid escaped format for Chromium App-Bound key: {str(e)}") from e

        # Try to parse as hex format (64 hex characters = 32 bytes)
        if re.match(r"^[0-9a-fA-F]+$", v):
            if len(v) != 64:
                raise ValueError(
                    f"Chromium App-Bound key in hex format must be exactly 64 hex characters (32 bytes), got {len(v)} characters"
                )
            return v

        raise ValueError(
            "Chromium App-Bound key must be either 64 hex characters or Python escaped format (\\x5f\\x1a...)"
        )


def get_credential_type(v):
    """Discriminator function to determine credential type from 'type' field."""
    if isinstance(v, dict):
        return v.get("type")
    return getattr(v, "type", None)


type DpapiCredentialRequest = Annotated[
    Annotated[PasswordCredentialKey, Tag("password")]
    | Annotated[NtlmHashCredentialKey, Tag("cred_key_ntlm")]
    | Annotated[Sha1CredentialKey, Tag("cred_key_sha1")]
    | Annotated[Pbkdf2StrongCredentialKey, Tag("cred_key_pbkdf2")]
    | Annotated[DomainBackupKeyCredential, Tag("domain_backup_key")]
    | Annotated[MasterKeyGuidPairList, Tag("master_key_guid_pair")]
    | Annotated[DpapiSystemCredentialRequest, Tag("dpapi_system")]
    | Annotated[ChromiumAppBoundKeyCredential, Tag("chromium_app_bound_key")],
    Field(discriminator=Discriminator(get_credential_type)),
]
