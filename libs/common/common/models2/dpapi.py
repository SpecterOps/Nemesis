"""DPAPI credential models for API requests."""

import re
from typing import Literal
from uuid import UUID

from nemesis_dpapi.types import Sid
from pydantic import BaseModel, Field, field_serializer, field_validator


class PasswordCredential(BaseModel):
    """Plain text password credential requiring user SID."""

    type: Literal["password"]
    value: str  # Plain text password
    user_sid: Sid  # Required for password-based credentials


class NtlmHashCredential(BaseModel):
    """NTLM hash credential requiring user SID."""

    type: Literal["ntlm_hash"]
    value: str  # Hex string representation of NTLM hash
    user_sid: Sid  # Required for NTLM hash credentials


class CredKeyCredential(BaseModel):
    """Credential key requiring user SID."""

    type: Literal["cred_key"]
    value: str  # Hex string representation of credential key
    user_sid: Sid  # Required for credential key


class DomainBackupKeyCredential(BaseModel):
    """Domain backup key credential (PVK format)."""

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


class MasterKeyData(BaseModel):
    """Strongly typed master key data."""

    guid: UUID = Field(description="Master key GUID")
    key_hex: str = Field(
        description="Hex-encoded master key bytes", pattern=r"^[0-9a-fA-F]+$"
    )

    @field_serializer("guid")
    def serialize_guid(self, value: UUID) -> str:
        return str(value)


class DecryptedMasterKeyCredential(BaseModel):
    """Pre-decrypted master key with strongly typed data."""

    type: Literal["dec_master_key"]
    value: list[MasterKeyData]


class DpapiSystemCredentialRequest(BaseModel):
    """DPAPI_SYSTEM LSA Secret credential sent in an API request."""

    # TODO: Make this use DpapiSystemCredential from nemesis_dpapi core

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
            raise ValueError(
                "DPAPI_SYSTEM value must contain only hex characters (0-9, a-f, A-F)"
            )
        return v


type DpapiCredentialRequest = (
    PasswordCredential
    | NtlmHashCredential
    | CredKeyCredential
    | DomainBackupKeyCredential
    | DecryptedMasterKeyCredential
    | DpapiSystemCredentialRequest
)
