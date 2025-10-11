"""Tests for write-once semantics in upsert operations."""

from uuid import UUID, uuid4

import pytest

from nemesis_dpapi.core import MasterKey, MasterKeyType
from nemesis_dpapi.exceptions import WriteOnceViolationError
from nemesis_dpapi.keys import DomainBackupKey
from nemesis_dpapi.manager import DpapiManager


class TestMasterKeyWriteOnce:
    """Test write-once semantics for masterkey upserts."""

    @pytest.mark.asyncio
    async def test_insert_new_masterkey(self):
        """Should successfully insert a new masterkey."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()
            masterkey = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                encrypted_key_usercred=b"encrypted_data",
                plaintext_key=b"plaintext_key_data",
            )

            await manager.upsert_masterkey(masterkey)

            # Verify it was inserted
            result = await manager.get_masterkeys(guid=guid)
            assert len(result) == 1
            assert result[0].guid == guid

    @pytest.mark.asyncio
    async def test_idempotent_update_with_same_values(self):
        """Should allow updating with identical values (idempotent)."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()
            masterkey = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                encrypted_key_usercred=b"encrypted_data",
            )

            # First insert
            await manager.upsert_masterkey(masterkey)

            # Second insert with same values should succeed
            await manager.upsert_masterkey(masterkey)

            # Verify
            result = await manager.get_masterkeys(guid=guid)
            assert len(result) == 1

    @pytest.mark.asyncio
    async def test_reject_changing_encrypted_key_usercred(self):
        """Should reject attempt to change encrypted_key_usercred."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()

            # First insert
            masterkey1 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                encrypted_key_usercred=b"original_data",
            )
            await manager.upsert_masterkey(masterkey1)

            # Try to change encrypted_key_usercred
            masterkey2 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                encrypted_key_usercred=b"different_data",
            )

            with pytest.raises(WriteOnceViolationError) as exc_info:
                await manager.upsert_masterkey(masterkey2)

            # Verify error details
            assert exc_info.value.entity_type == "masterkey"
            assert exc_info.value.entity_id == str(guid)
            assert "encrypted_key_usercred" in exc_info.value.fields

    @pytest.mark.asyncio
    async def test_reject_changing_plaintext_key(self):
        """Should reject attempt to change plaintext_key."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()

            # First insert with plaintext
            masterkey1 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                plaintext_key=b"original_plaintext",
            )
            await manager.upsert_masterkey(masterkey1)

            # Try to change plaintext_key
            masterkey2 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                plaintext_key=b"different_plaintext",
            )

            with pytest.raises(WriteOnceViolationError) as exc_info:
                await manager.upsert_masterkey(masterkey2)

            assert "plaintext_key" in exc_info.value.fields

    @pytest.mark.asyncio
    async def test_reject_changing_masterkey_type(self):
        """Should reject attempt to change masterkey_type (strict enforcement)."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()

            # First insert as UNKNOWN
            masterkey1 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.UNKNOWN,
            )
            await manager.upsert_masterkey(masterkey1)

            # Try to change to USER (even though it's a refinement, we're strict)
            masterkey2 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
            )

            with pytest.raises(WriteOnceViolationError) as exc_info:
                await manager.upsert_masterkey(masterkey2)

            assert "masterkey_type" in exc_info.value.fields

    @pytest.mark.asyncio
    async def test_allow_filling_null_fields(self):
        """Should allow writing to previously NULL fields."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()

            # First insert with only encrypted data
            masterkey1 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                encrypted_key_usercred=b"encrypted_data",
            )
            await manager.upsert_masterkey(masterkey1)

            # Add plaintext_key (previously NULL)
            masterkey2 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                encrypted_key_usercred=b"encrypted_data",  # Same
                plaintext_key=b"now_decrypted",  # New
            )
            await manager.upsert_masterkey(masterkey2)

            # Verify both fields are set
            result = await manager.get_masterkeys(guid=guid)
            assert result[0].encrypted_key_usercred == b"encrypted_data"
            assert result[0].plaintext_key == b"now_decrypted"

    @pytest.mark.asyncio
    async def test_reject_clearing_non_null_field(self):
        """Should reject attempt to set non-NULL field to NULL."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()

            # First insert with plaintext
            masterkey1 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                plaintext_key=b"plaintext_data",
            )
            await manager.upsert_masterkey(masterkey1)

            # Try to clear plaintext_key
            masterkey2 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                plaintext_key=None,  # Trying to clear
            )

            with pytest.raises(WriteOnceViolationError) as exc_info:
                await manager.upsert_masterkey(masterkey2)

            assert "plaintext_key" in exc_info.value.fields

    @pytest.mark.asyncio
    async def test_sha1_auto_calculation(self):
        """Should auto-calculate SHA1 when plaintext_key is provided."""
        async with DpapiManager(storage_backend="memory") as manager:
            from Crypto.Hash import SHA1

            guid = uuid4()
            plaintext = b"my_plaintext_key"
            expected_sha1 = SHA1.new(plaintext).digest()

            masterkey = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                plaintext_key=plaintext,
                # Note: plaintext_key_sha1 not provided
            )
            await manager.upsert_masterkey(masterkey)

            # Verify SHA1 was calculated
            result = await manager.get_masterkeys(guid=guid)
            assert result[0].plaintext_key_sha1 == expected_sha1

    @pytest.mark.asyncio
    async def test_sha1_verification_rejects_mismatch(self):
        """Should reject when provided SHA1 doesn't match plaintext_key."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()

            masterkey = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                plaintext_key=b"my_plaintext_key",
                plaintext_key_sha1=b"0" * 20,  # Wrong SHA1
            )

            with pytest.raises(ValueError, match="does not match calculated SHA1"):
                await manager.upsert_masterkey(masterkey)

    @pytest.mark.asyncio
    async def test_sha1_verification_accepts_correct_hash(self):
        """Should accept when provided SHA1 matches plaintext_key."""
        async with DpapiManager(storage_backend="memory") as manager:
            from Crypto.Hash import SHA1

            guid = uuid4()
            plaintext = b"my_plaintext_key"
            correct_sha1 = SHA1.new(plaintext).digest()

            masterkey = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                plaintext_key=plaintext,
                plaintext_key_sha1=correct_sha1,
            )

            await manager.upsert_masterkey(masterkey)

            # Verify
            result = await manager.get_masterkeys(guid=guid)
            assert result[0].plaintext_key_sha1 == correct_sha1

    @pytest.mark.asyncio
    async def test_sha1_only_update(self):
        """Should allow updating only SHA1 without plaintext_key."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()
            sha1_value = b"1" * 20

            masterkey = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                plaintext_key_sha1=sha1_value,  # Only SHA1
            )

            await manager.upsert_masterkey(masterkey)

            # Verify
            result = await manager.get_masterkeys(guid=guid)
            assert result[0].plaintext_key_sha1 == sha1_value
            assert result[0].plaintext_key is None

    @pytest.mark.asyncio
    async def test_multiple_field_conflicts(self):
        """Should detect multiple field conflicts."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()

            # First insert
            masterkey1 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                encrypted_key_usercred=b"encrypted1",
                plaintext_key=b"plaintext1",
            )
            await manager.upsert_masterkey(masterkey1)

            # Try to change both
            masterkey2 = MasterKey(
                guid=guid,
                masterkey_type=MasterKeyType.USER,
                encrypted_key_usercred=b"encrypted2",  # Changed
                plaintext_key=b"plaintext2",  # Changed
            )

            with pytest.raises(WriteOnceViolationError) as exc_info:
                await manager.upsert_masterkey(masterkey2)

            # Should report both conflicts
            assert "encrypted_key_usercred" in exc_info.value.fields
            assert "plaintext_key" in exc_info.value.fields


class TestDomainBackupKeyWriteOnce:
    """Test write-once semantics for domain backup key upserts."""

    def _create_valid_backup_key_data(self) -> bytes:
        """Create valid PVK file header + private key data for testing."""
        # This is a minimal valid PVK structure for testing
        # In real scenarios, this would be actual RSA private key data
        import struct

        PVK_MAGIC = 0xB0B5F11E
        PVK_VERSION = 0
        KEY_SPEC = 1
        ENCRYPT_TYPE = 0
        ENCRYPT_DATA_SIZE = 0
        PVK_SIZE = 20  # Minimal size

        header = struct.pack(
            "<6I",
            PVK_MAGIC,
            PVK_VERSION,
            KEY_SPEC,
            ENCRYPT_TYPE,
            ENCRYPT_DATA_SIZE,
            PVK_SIZE,
        )

        # Add minimal private key data (would be actual PRIVATE_KEY_BLOB in real usage)
        private_key = b"\x00" * PVK_SIZE

        return header + private_key

    @pytest.mark.asyncio
    async def test_insert_new_backup_key(self):
        """Should successfully insert a new domain backup key."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()
            key_data = self._create_valid_backup_key_data()

            backup_key = DomainBackupKey(
                guid=guid,
                key_data=key_data,
                domain_controller="DC01.contoso.com",
            )

            await manager.upsert_domain_backup_key(backup_key)

            # Verify
            result = await manager.get_backup_keys(guid=guid)
            assert len(result) == 1
            assert result[0].guid == guid

    @pytest.mark.asyncio
    async def test_idempotent_update_backup_key(self):
        """Should allow idempotent updates."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()
            key_data = self._create_valid_backup_key_data()

            backup_key = DomainBackupKey(
                guid=guid,
                key_data=key_data,
            )

            await manager.upsert_domain_backup_key(backup_key)
            await manager.upsert_domain_backup_key(backup_key)  # Should succeed

            result = await manager.get_backup_keys(guid=guid)
            assert len(result) == 1

    @pytest.mark.asyncio
    async def test_reject_changing_key_data(self):
        """Should reject attempt to change key_data."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()
            key_data1 = self._create_valid_backup_key_data()
            key_data2 = self._create_valid_backup_key_data() + b"\xFF"  # Different

            # First insert
            backup_key1 = DomainBackupKey(guid=guid, key_data=key_data1)
            await manager.upsert_domain_backup_key(backup_key1)

            # Try to change
            backup_key2 = DomainBackupKey(guid=guid, key_data=key_data2)

            with pytest.raises(WriteOnceViolationError) as exc_info:
                await manager.upsert_domain_backup_key(backup_key2)

            assert exc_info.value.entity_type == "backup_key"
            assert "key_data" in exc_info.value.fields

    @pytest.mark.asyncio
    async def test_reject_changing_domain_controller(self):
        """Should reject attempt to change domain_controller."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()
            key_data = self._create_valid_backup_key_data()

            # First insert
            backup_key1 = DomainBackupKey(
                guid=guid,
                key_data=key_data,
                domain_controller="DC01.contoso.com",
            )
            await manager.upsert_domain_backup_key(backup_key1)

            # Try to change domain_controller
            backup_key2 = DomainBackupKey(
                guid=guid,
                key_data=key_data,
                domain_controller="DC02.contoso.com",  # Different
            )

            with pytest.raises(WriteOnceViolationError) as exc_info:
                await manager.upsert_domain_backup_key(backup_key2)

            assert "domain_controller" in exc_info.value.fields

    @pytest.mark.asyncio
    async def test_allow_filling_null_domain_controller(self):
        """Should allow setting domain_controller when previously NULL."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()
            key_data = self._create_valid_backup_key_data()

            # First insert without domain_controller
            backup_key1 = DomainBackupKey(guid=guid, key_data=key_data)
            await manager.upsert_domain_backup_key(backup_key1)

            # Add domain_controller
            backup_key2 = DomainBackupKey(
                guid=guid,
                key_data=key_data,
                domain_controller="DC01.contoso.com",
            )
            await manager.upsert_domain_backup_key(backup_key2)

            # Verify
            result = await manager.get_backup_keys(guid=guid)
            assert result[0].domain_controller == "DC01.contoso.com"

    @pytest.mark.asyncio
    async def test_reject_empty_string_domain_controller(self):
        """Should reject empty string for domain_controller."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()
            key_data = self._create_valid_backup_key_data()

            backup_key = DomainBackupKey(
                guid=guid,
                key_data=key_data,
                domain_controller="",  # Empty string
            )

            with pytest.raises(ValueError, match="cannot be empty string"):
                await manager.upsert_domain_backup_key(backup_key)

    @pytest.mark.asyncio
    async def test_case_sensitive_domain_controller(self):
        """Should treat domain_controller as case-sensitive."""
        async with DpapiManager(storage_backend="memory") as manager:
            guid = uuid4()
            key_data = self._create_valid_backup_key_data()

            # First insert with uppercase
            backup_key1 = DomainBackupKey(
                guid=guid,
                key_data=key_data,
                domain_controller="DC01.CONTOSO.COM",
            )
            await manager.upsert_domain_backup_key(backup_key1)

            # Try with lowercase (different value due to case sensitivity)
            backup_key2 = DomainBackupKey(
                guid=guid,
                key_data=key_data,
                domain_controller="dc01.contoso.com",
            )

            with pytest.raises(WriteOnceViolationError):
                await manager.upsert_domain_backup_key(backup_key2)


class TestSystemCredentialWriteOnce:
    """Test that system credentials already have write-once semantics."""

    @pytest.mark.asyncio
    async def test_system_credentials_already_write_once(self):
        """System credentials should already use DO NOTHING (no changes needed)."""
        from nemesis_dpapi.keys import DpapiSystemCredential

        async with DpapiManager(storage_backend="memory", auto_decrypt=False) as manager:
            # First insert
            cred1 = DpapiSystemCredential(user_key=b"0" * 20, machine_key=b"1" * 20)
            await manager.upsert_system_credential(cred1)

            # Second insert with same keys (should succeed, idempotent)
            cred2 = DpapiSystemCredential(user_key=b"0" * 20, machine_key=b"1" * 20)
            await manager.upsert_system_credential(cred2)

            # Verify
            result = await manager.get_system_credentials()
            assert len(result) == 1
