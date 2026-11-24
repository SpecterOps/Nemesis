"""Tests for DPAPI eventing."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from nemesis_dpapi.eventing import (
    DPAPI_EVENT_CLASSES,
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
            "evnt": {"project": "proj-a", "masterkey_guid": str(masterkey_guid), "timestamp": timestamp.isoformat()},
        }

        typed_event = TypedDpapiEvent(**data)

        assert typed_event.type_name == "NewPlaintextMasterKeyEvent"
        assert isinstance(typed_event.evnt, NewPlaintextMasterKeyEvent)
        assert typed_event.evnt.masterkey_guid == masterkey_guid
        assert typed_event.evnt.project == "proj-a"

    def test_deserialize_from_already_instantiated_event(self):
        """Test deserializing when event is already an instance (not a dict)."""
        masterkey_guid = UUID("12345678-1234-5678-1234-567812345678")
        timestamp = datetime.now(UTC)

        event = NewPlaintextMasterKeyEvent(project="proj-a", masterkey_guid=masterkey_guid, timestamp=timestamp)

        data = {"type_name": "NewPlaintextMasterKeyEvent", "evnt": event}

        typed_event = TypedDpapiEvent(**data)

        assert typed_event.type_name == "NewPlaintextMasterKeyEvent"
        assert isinstance(typed_event.evnt, NewPlaintextMasterKeyEvent)
        assert typed_event.evnt.masterkey_guid == masterkey_guid
        assert typed_event.evnt.project == "proj-a"

    def test_deserialize_encrypted_masterkey_event(self):
        """Test deserializing NewEncryptedMasterKeyEvent."""
        masterkey_guid = UUID("87654321-4321-8765-4321-876543218765")

        data = {
            "type_name": "NewEncryptedMasterKeyEvent",
            "evnt": {"project": "proj-a", "masterkey_guid": str(masterkey_guid)},
        }

        typed_event = TypedDpapiEvent(**data)

        assert isinstance(typed_event.evnt, NewEncryptedMasterKeyEvent)
        assert typed_event.evnt.masterkey_guid == masterkey_guid
        assert typed_event.evnt.project == "proj-a"

    def test_deserialize_domain_backup_key_event(self):
        """Test deserializing NewDomainBackupKeyEvent."""
        backup_key_guid = UUID("11111111-2222-3333-4444-555555555555")

        data = {
            "type_name": "NewDomainBackupKeyEvent",
            "evnt": {"project": "proj-a", "backup_key_guid": str(backup_key_guid)},
        }

        typed_event = TypedDpapiEvent(**data)

        assert isinstance(typed_event.evnt, NewDomainBackupKeyEvent)
        assert typed_event.evnt.backup_key_guid == backup_key_guid

    def test_deserialize_dpapi_system_credential_event(self):
        """Test deserializing NewDpapiSystemCredentialEvent."""
        cred = DpapiSystemCredential(machine_key=b"0" * 20, user_key=b"1" * 20)

        data = {
            "type_name": "NewDpapiSystemCredentialEvent",
            "evnt": {"project": "proj-a", "credential": cred.model_dump()},
        }

        typed_event = TypedDpapiEvent(**data)

        assert isinstance(typed_event.evnt, NewDpapiSystemCredentialEvent)
        assert typed_event.evnt.credential.machine_key == b"0" * 20
        assert typed_event.evnt.credential.user_key == b"1" * 20

    def test_deserialize_password_derived_credential_event(self):
        """Test deserializing NewPasswordDerivedCredentialEvent."""
        password = Password(value="test123")
        user_sid = "S-1-5-21-1234567890-1234567890-1234567890-1001"

        data = {
            "type_name": "NewPasswordDerivedCredentialEvent",
            "evnt": {
                "project": "proj-a",
                "type": "Password",
                "credential": password.model_dump(),
                "user_sid": str(user_sid),
            },
        }

        typed_event = TypedDpapiEvent(**data)

        assert isinstance(typed_event.evnt, NewPasswordDerivedCredentialEvent)
        assert typed_event.evnt.type == "Password"
        assert isinstance(typed_event.evnt.credential, Password)
        assert typed_event.evnt.credential.value == "test123"
        assert typed_event.evnt.user_sid == user_sid

    def test_deserialize_ntlm_hash_credential_event(self):
        """Test deserializing NewPasswordDerivedCredentialEvent with NTLM hash."""
        ntlm_hash = NtlmHash(value=b"0" * 16)

        data = {
            "type_name": "NewPasswordDerivedCredentialEvent",
            "evnt": {
                "project": "proj-a",
                "type": "NtlmHash",
                "credential": ntlm_hash.model_dump(),
            },
        }

        typed_event = TypedDpapiEvent(**data)

        assert isinstance(typed_event.evnt, NewPasswordDerivedCredentialEvent)
        assert typed_event.evnt.type == "NtlmHash"
        assert isinstance(typed_event.evnt.credential, NtlmHash)


class TestEventProject:
    """Every DPAPI event names its project so observers can stay within it."""

    @pytest.mark.parametrize(
        ("type_name", "evnt"),
        [
            ("NewPlaintextMasterKeyEvent", {"masterkey_guid": "12345678-1234-5678-9abc-123456789abc"}),
            ("NewEncryptedMasterKeyEvent", {"masterkey_guid": "12345678-1234-5678-9abc-123456789abc"}),
            ("NewDomainBackupKeyEvent", {"backup_key_guid": "12345678-1234-5678-9abc-123456789abc"}),
        ],
    )
    def test_project_is_required(self, type_name, evnt):
        with pytest.raises(ValueError):
            DPAPI_EVENT_CLASSES[type_name](**evnt)

    def test_project_survives_round_trip(self):
        event = NewDomainBackupKeyEvent(project="proj-b", backup_key_guid=uuid4())
        restored = TypedDpapiEvent(**TypedDpapiEvent(type_name="NewDomainBackupKeyEvent", evnt=event).model_dump())
        assert restored.evnt.project == "proj-b"
