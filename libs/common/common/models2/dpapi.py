"""DPAPI credential models for API requests."""

import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, BeforeValidator, field_serializer


def validate_windows_sid(value: str) -> str:
    """Validate that a string is a valid Windows SID format.
    
    Windows SIDs have the format: S-R-I-S-S-...-S
    Where:
    - S = literal 'S'
    - R = revision (usually 1)
    - I = identifier authority (48-bit number)
    - S = subauthority values (32-bit numbers)
    
    Examples:
    - S-1-5-21-1234567890-1234567890-1234567890-1001 (domain user)
    - S-1-5-18 (local system)
    - S-1-5-32-544 (builtin administrators)
    """
    if not isinstance(value, str):
        raise ValueError("SID must be a string")
    
    # Basic format check: starts with S-, all parts are numeric except first
    sid_pattern = r'^S-\d+(-\d+)*$'
    
    if not re.match(sid_pattern, value):
        raise ValueError(f"Invalid Windows SID format: {value}")
    
    # Split and validate components
    parts = value.split('-')
    
    # Must have at least S-R-I-S (4 parts after splitting - need at least one subauthority)
    if len(parts) < 4:
        raise ValueError(f"SID must have at least one subauthority: {value}")
    
    # First part must be 'S'
    if parts[0] != 'S':
        raise ValueError(f"SID must start with 'S': {value}")
    
    # Second part is revision (should be 1)
    try:
        revision = int(parts[1])
        if revision != 1:
            raise ValueError(f"SID revision must be 1, got {revision}: {value}")
    except ValueError as e:
        # Re-raise specific revision errors, but catch non-numeric revision errors
        if "SID revision must be 1" in str(e):
            raise e
        raise ValueError(f"Invalid SID revision: {value}") from e
    
    # Validate all numeric parts are valid integers
    for i, part in enumerate(parts[2:], start=2):
        try:
            num_val = int(part)
            # Authority and subauthority values should be non-negative
            if num_val < 0:
                raise ValueError(f"SID component at position {i} must be non-negative: {value}")
        except ValueError as e:
            raise ValueError(f"Invalid numeric component in SID at position {i}: {value}") from e
    
    return value


# Annotated type for Windows SID validation
Sid = Annotated[str, BeforeValidator(validate_windows_sid)]


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
    
    @field_serializer('guid')
    def serialize_guid(self, value: UUID) -> str:
        return str(value)


class DecryptedMasterKeyCredential(BaseModel):
    """Pre-decrypted master key with strongly typed data."""

    type: Literal["dec_master_key"]
    value: MasterKeyData


type DpapiCredentialRequest = (
    PasswordCredential
    | NtlmHashCredential
    | CredKeyCredential
    | DomainBackupKeyCredential
    | DecryptedMasterKeyCredential
)
