"""DPAPI credential models for API requests."""

from typing import Literal, Union

from pydantic import BaseModel


class PasswordCredential(BaseModel):
    """Plain text password credential requiring user SID."""

    type: Literal["password"]
    value: str  # Plain text password
    user_sid: str  # Required for password-based credentials


class NtlmHashCredential(BaseModel):
    """NTLM hash credential requiring user SID."""

    type: Literal["ntlm_hash"]
    value: str  # Hex string representation of NTLM hash
    user_sid: str  # Required for NTLM hash credentials


class CredKeyCredential(BaseModel):
    """Credential key requiring user SID."""

    type: Literal["cred_key"]
    value: str  # Hex string representation of credential key
    user_sid: str  # Required for credential key


class DomainBackupKeyCredential(BaseModel):
    """Domain backup key credential (PVK format)."""

    type: Literal["domain_backup_key"]
    value: str  # Base64 encoded PVK data


class DecryptedMasterKeyCredential(BaseModel):
    """Pre-decrypted master key."""

    type: Literal["dec_master_key"]
    value: str  # Format: {guid}:key_hex


# Discriminated Union type for all possible credential types
DpapiCredentialRequest = Union[
    PasswordCredential,
    NtlmHashCredential,
    CredKeyCredential,
    DomainBackupKeyCredential,
    DecryptedMasterKeyCredential,
]
