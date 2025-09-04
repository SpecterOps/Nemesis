from pydantic import BaseModel


class EnrichmentRequest(BaseModel):
    object_id: str


class CleanupRequest(BaseModel):
    expiration: str | None = None  # ISO datetime or "all"


class DpapiCredentialRequest(BaseModel):
    type: str  # password, ntlm_hash, cred_key, domain_backup_key, dec_master_key
    value: str
    user_sid: str | None = None  # Required for password, ntlm_hash, cred_key
