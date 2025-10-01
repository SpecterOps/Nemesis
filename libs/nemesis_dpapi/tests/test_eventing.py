"""Tests for DPAPI eventing."""

from datetime import UTC, datetime
from uuid import UUID

from nemesis_dpapi.eventing import (
    NewDomainBackupKeyEvent,
    NewDpapiSystemCredentialEvent,
    NewEncryptedMasterKeyEvent,
    NewPasswordDerivedCredentialEvent,
    NewPlaintextMasterKeyEvent,
    TypedDpapiEvent,
)
from nemesis_dpapi.keys import DpapiSystemCredential, NtlmHash, Password


class TestTypedDpapiEventDeserialization:
    """Test TypedDpapiEvent deserialization."""

    def test_deserialize_from_dict(self):
        """Test deserializing TypedDpapiEvent from dictionary."""
        masterkey_guid = UUID("12345678-1234-5678-1234-567812345678")
        timestamp = datetime.now(UTC)

        data = {
            "type_name": "NewPlaintextMasterKeyEvent",
            "event": {"masterkey_guid": str(masterkey_guid), "timestamp": timestamp.isoformat()},
        }

        typed_event = TypedDpapiEvent(**data)

        assert typed_event.type_name == "NewPlaintextMasterKeyEvent"
        assert isinstance(typed_event.event, NewPlaintextMasterKeyEvent)
        assert typed_event.event.masterkey_guid == masterkey_guid

    def test_deserialize_from_already_instantiated_event(self):
        """Test deserializing when event is already an instance (not a dict)."""
        masterkey_guid = UUID("12345678-1234-5678-1234-567812345678")
        timestamp = datetime.now(UTC)

        event = NewPlaintextMasterKeyEvent(masterkey_guid=masterkey_guid, timestamp=timestamp)

        data = {"type_name": "NewPlaintextMasterKeyEvent", "event": event}

        typed_event = TypedDpapiEvent(**data)

        assert typed_event.type_name == "NewPlaintextMasterKeyEvent"
        assert isinstance(typed_event.event, NewPlaintextMasterKeyEvent)
        assert typed_event.event.masterkey_guid == masterkey_guid

    def test_deserialize_encrypted_masterkey_event(self):
        """Test deserializing NewEncryptedMasterKeyEvent."""
        masterkey_guid = UUID("87654321-4321-8765-4321-876543218765")

        data = {
            "type_name": "NewEncryptedMasterKeyEvent",
            "event": {"masterkey_guid": str(masterkey_guid)},
        }

        typed_event = TypedDpapiEvent(**data)

        assert isinstance(typed_event.event, NewEncryptedMasterKeyEvent)
        assert typed_event.event.masterkey_guid == masterkey_guid

    def test_deserialize_domain_backup_key_event(self):
        """Test deserializing NewDomainBackupKeyEvent."""
        backup_key_guid = UUID("11111111-2222-3333-4444-555555555555")

        data = {"type_name": "NewDomainBackupKeyEvent", "event": {"backup_key_guid": str(backup_key_guid)}}

        typed_event = TypedDpapiEvent(**data)

        assert isinstance(typed_event.event, NewDomainBackupKeyEvent)
        assert typed_event.event.backup_key_guid == backup_key_guid

    def test_deserialize_dpapi_system_credential_event(self):
        """Test deserializing NewDpapiSystemCredentialEvent."""
        cred = DpapiSystemCredential(machine_key=b"0" * 20, user_key=b"1" * 20)

        data = {
            "type_name": "NewDpapiSystemCredentialEvent",
            "event": {"credential": cred.model_dump()},
        }

        typed_event = TypedDpapiEvent(**data)

        assert isinstance(typed_event.event, NewDpapiSystemCredentialEvent)
        assert typed_event.event.credential.machine_key == b"0" * 20
        assert typed_event.event.credential.user_key == b"1" * 20

    def test_deserialize_password_derived_credential_event(self):
        """Test deserializing NewPasswordDerivedCredentialEvent."""
        password = Password(value="test123")
        user_sid = "S-1-5-21-1234567890-1234567890-1234567890-1001"

        data = {
            "type_name": "NewPasswordDerivedCredentialEvent",
            "event": {
                "type": "Password",
                "credential": password.model_dump(),
                "user_sid": str(user_sid),
            },
        }

        typed_event = TypedDpapiEvent(**data)

        assert isinstance(typed_event.event, NewPasswordDerivedCredentialEvent)
        assert typed_event.event.type == "Password"
        assert isinstance(typed_event.event.credential, Password)
        assert typed_event.event.credential.value == "test123"
        assert typed_event.event.user_sid == user_sid

    def test_deserialize_ntlm_hash_credential_event(self):
        """Test deserializing NewPasswordDerivedCredentialEvent with NTLM hash."""
        ntlm_hash = NtlmHash(value=b"0" * 16)

        data = {
            "type_name": "NewPasswordDerivedCredentialEvent",
            "event": {
                "type": "NtlmHash",
                "credential": ntlm_hash.model_dump(),
            },
        }

        typed_event = TypedDpapiEvent(**data)

        assert isinstance(typed_event.event, NewPasswordDerivedCredentialEvent)
        assert typed_event.event.type == "NtlmHash"
        assert isinstance(typed_event.event.credential, NtlmHash)
