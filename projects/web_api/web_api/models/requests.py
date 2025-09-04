from pydantic import BaseModel
from common.models2.dpapi import (
    CredKeyCredential,
    DecryptedMasterKeyCredential,
    DomainBackupKeyCredential,
    DpapiCredentialRequest,
    NtlmHashCredential,
    PasswordCredential,
)


class EnrichmentRequest(BaseModel):
    object_id: str


class CleanupRequest(BaseModel):
    expiration: str | None = None  # ISO datetime or "all"
