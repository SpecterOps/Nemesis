"""Tests for DPAPI core models."""

import asyncio
import base64
import json
from pathlib import Path
from uuid import UUID

import pytest
from dpapi.core import Blob, DomainBackupKey, MasterKeyFile, MasterKeyPolicy
from dpapi.crypto import MasterKeyDecryptionError
from dpapi.manager import DpapiManager


class TestMasterKeyFile:
    """Tests for MasterKeyFile class."""

    def test_parse_valid_masterkey_file_domain(self):
        """Test parsing a valid masterkey file from a domain user."""
        test_file = Path("tests/fixtures/masterkey_domain.bin")

        masterkey = MasterKeyFile.parse(test_file)

        # Verify basic structure
        assert isinstance(masterkey, MasterKeyFile)
        assert isinstance(masterkey.version, int)
        assert masterkey.version == 2
        assert isinstance(masterkey.modified, bool)
        assert isinstance(masterkey.masterkey_guid, UUID)
        assert masterkey.masterkey_guid == UUID("ed93694f-5a6d-46e2-b821-219f2c0ecd4d")
        assert isinstance(masterkey.policy, MasterKeyPolicy)
        assert masterkey.policy == (MasterKeyPolicy.NONE)

        # File path should be set to the parsed file path
        assert masterkey.file_path is None
        assert masterkey.master_key and len(masterkey.master_key) == 176
        assert masterkey.local_key and len(masterkey.local_key) == 144
        assert not masterkey.backup_key
        assert masterkey.domain_backup_key and len(masterkey.domain_backup_key) == 428

    def test_parse_valid_masterkey_file_local(self):
        """Test parsing a valid masterkey file from a local account."""
        test_file = Path("tests/fixtures/masterkey_local.bin")

        masterkey = MasterKeyFile.parse(test_file)

        # Verify basic structure
        assert isinstance(masterkey, MasterKeyFile)
        assert isinstance(masterkey.version, int)
        assert masterkey.version == 2
        assert isinstance(masterkey.modified, bool)
        assert isinstance(masterkey.masterkey_guid, UUID)
        assert masterkey.masterkey_guid == UUID("387a062d-f8b6-4661-b2c5-eecbb9f80afb")
        assert isinstance(masterkey.policy, MasterKeyPolicy)
        assert masterkey.policy == (MasterKeyPolicy.LOCAL_BACKUP | MasterKeyPolicy.DPAPI_OWF)

        # File path should be set to the parsed file path
        assert masterkey.file_path is None
        assert masterkey.master_key and len(masterkey.master_key) == 176
        assert masterkey.local_key and len(masterkey.local_key) == 144
        assert masterkey.backup_key and len(masterkey.backup_key) == 20
        assert not masterkey.domain_backup_key

    def test_parse_nonexistent_file(self):
        """Test parsing a non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            MasterKeyFile.parse("nonexistent_file.bin")

    def test_parse_empty_file(self, tmp_path):
        """Test parsing an empty file raises ValueError."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        with pytest.raises(ValueError, match="File too small"):
            MasterKeyFile.parse(empty_file)

    def test_parse_truncated_header(self, tmp_path):
        """Test parsing a file with truncated header raises ValueError."""
        truncated_file = tmp_path / "truncated.bin"
        truncated_file.write_bytes(b"truncated_data_too_short")

        with pytest.raises(ValueError, match="File too small"):
            MasterKeyFile.parse(truncated_file)

    def test_parse_invalid_size(self, tmp_path):
        """Test parsing a file with invalid key data size raises ValueError."""
        invalid_file = tmp_path / "invalid.bin"

        # Create a minimal header that claims more data than available
        import struct

        header = struct.pack(
            "<III80sIIIIIIIII",
            1,  # version
            0,  # modified
            0,  # szFilePath
            "{12345678-1234-5678-9abc-123456789abc}".encode("utf-16le").ljust(80, b"\x00"),  # guid
            0,  # policy
            1000,  # cbMK - claims 1000 bytes
            0,  # pbMK
            0,  # cbLK
            0,  # pbLK
            0,  # cbBK
            0,  # pbBK
            0,  # cbBBK
            0,  # pbBBK
        )
        invalid_file.write_bytes(header)

        with pytest.raises(ValueError, match="File size doesn't match expected key data size"):
            MasterKeyFile.parse(invalid_file)

    def test_policy_flags(self):
        """Test MasterKeyPolicy flag combinations."""
        # Test individual flags
        assert MasterKeyPolicy.LOCAL_BACKUP == 0x1
        assert MasterKeyPolicy.NO_BACKUP == 0x2
        assert MasterKeyPolicy.DPAPI_OWF == 0x4

        # Test flag combinations
        combined = MasterKeyPolicy.LOCAL_BACKUP | MasterKeyPolicy.DPAPI_OWF
        assert combined == 0x5
        assert MasterKeyPolicy.LOCAL_BACKUP in combined
        assert MasterKeyPolicy.DPAPI_OWF in combined
        assert MasterKeyPolicy.NO_BACKUP not in combined

    def test_optional_keys(self, tmp_path):
        """Test parsing file with some keys missing."""
        test_file = tmp_path / "optional_keys.bin"

        import struct

        # Create header with only master key data
        guid_bytes = "{12345678-1234-5678-9abc-123456789abc}".encode("utf-16le")
        guid_padded = guid_bytes + b"\x00" * (80 - len(guid_bytes))

        header = struct.pack(
            "<III80sIIIIIIIII",
            1,  # version
            0,  # modified
            0,  # szFilePath
            guid_padded,  # guid
            MasterKeyPolicy.LOCAL_BACKUP.value,  # policy
            10,  # cbMK - has master key
            0,  # pbMK
            0,  # cbLK - no local key
            0,  # pbLK
            0,  # cbBK - no backup key
            0,  # pbBK
            0,  # cbBBK - no backup DC key
            0,  # pbBBK
        )

        # Add only master key data
        master_key_data = b"1234567890"
        test_file.write_bytes(header + master_key_data)

        masterkey = MasterKeyFile.parse(test_file)

        # Should have master key but not others
        assert masterkey.master_key is not None
        assert len(masterkey.master_key) == 10
        assert masterkey.local_key is None
        assert masterkey.backup_key is None
        assert masterkey.domain_backup_key is None


class TestBlob:
    """Tests for Blob class."""

    def test_parse_blob_with_entropy(self):
        """Test parsing a DPAPI blob with entropy data."""
        blob_with_entropy_b64 = "AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAT2mT7W1a4ka4ISGfLA7NTQAAAAACAAAAAAAQZgAAAAEAACAAAACaiwIebFUs33w09ku7t4/Du5UqIHgZYWB5wlb0ZVbAUQAAAAAOgAAAAAIAACAAAADlEO+UC16KILnjeGsNQeNKSA3rkgH143oMqetquuJKrhAAAAAgdVgTUj+tOxXBNhzgaet9QAAAAPgAbyIprGNvJeerbviVODBFa9R0rpBTZ/cV0Ca9geQ8xTIoizQnEFZo8vg5wfK111UtBt+FJOmZL18JIy+r1io="
        blob_data = base64.b64decode(blob_with_entropy_b64)

        blob = Blob.parse(blob_data)

        # Verify basic structure
        assert isinstance(blob, Blob)
        assert isinstance(blob.version, int)
        assert blob.version == 1
        assert isinstance(blob.masterkey_guid, UUID)
        assert blob.masterkey_guid == UUID("ed93694f-5a6d-46e2-b821-219f2c0ecd4d")
        assert isinstance(blob.prompt_flags, int)
        assert isinstance(blob.description, str)
        assert isinstance(blob.encryption_algorithm_id, int)
        assert isinstance(blob.encryption_algorithm_key_size, int)
        assert isinstance(blob.encryption_key, bytes)
        assert isinstance(blob.encryption_salt, bytes)
        assert isinstance(blob.mac_algorithm_id, int)
        assert isinstance(blob.mac_algorithm_key_size, int)
        assert isinstance(blob.mac_key, bytes)
        assert isinstance(blob.encrypted_data, bytes)
        assert isinstance(blob.mac, bytes)

        # Verify blob has encrypted data
        assert len(blob.encrypted_data) > 0
        assert len(blob.mac) > 0


class TestDomainBackupKey:
    """Test DomainBackupKey dataclass."""

    def test_create_domain_backup_key(self):
        """Test creating DomainBackupKey."""
        from uuid import uuid4

        guid = uuid4()
        key_data = b"backup_key_data_here"
        domain_controller = "DC01.example.com"

        backup_key = DomainBackupKey(guid=guid, key_data=key_data, domain_controller=domain_controller)

        assert backup_key.guid == guid
        assert backup_key.key_data == key_data
        assert backup_key.domain_controller == domain_controller

    def test_create_domain_backup_key_no_dc(self):
        """Test creating DomainBackupKey without domain controller."""
        from uuid import uuid4

        guid = uuid4()
        key_data = b"backup_key_data_here"

        backup_key = DomainBackupKey(guid=guid, key_data=key_data)

        assert backup_key.guid == guid
        assert backup_key.key_data == key_data
        assert backup_key.domain_controller is None

    def test_decrypt_masterkey_file_with_backup_key(self, get_file_path):
        """Test decrypting a domain masterkey file using backup key."""
        # Load the backup key from fixtures
        backupkey_file = get_file_path("backupkey.json")
        with open(backupkey_file) as f:
            backupkey_data = json.load(f)

        # Create DomainBackupKey from the fixture data
        backup_key = DomainBackupKey(
            guid=UUID(backupkey_data["backup_key_guid"]),
            key_data=base64.b64decode(backupkey_data["key"]),
            domain_controller=backupkey_data["dc"],
        )

        # Load the domain masterkey file
        masterkey_file = MasterKeyFile.parse(get_file_path("masterkey_domain.bin"))

        # Decrypt the masterkey
        decrypted_masterkey = backup_key.decrypt_masterkey_file(masterkey_file)

        # Verify decryption succeeded
        assert decrypted_masterkey is not None
        assert decrypted_masterkey.is_decrypted
        assert decrypted_masterkey.guid == masterkey_file.masterkey_guid
        assert decrypted_masterkey.plaintext_key is not None
        assert decrypted_masterkey.plaintext_key_sha1 is not None
        assert decrypted_masterkey.backup_key_guid == backup_key.guid
        assert len(decrypted_masterkey.plaintext_key_sha1) == 20  # SHA1 is 20 bytes

        masterkey_bytes = "36bd60cb9e7e52433169db00e93ed0a82d3c30c65d948bd8596fb32c267671020b02026b0ae03479dd18374adbdd7658f45cce6ed2a45319eff7a96c411c85f5"
        masterkey_sha1_hash = "17fd87f91d25a18abd9bcd66b6d9f3c6bfc16778"

        assert decrypted_masterkey.plaintext_key.hex() == masterkey_bytes
        assert decrypted_masterkey.plaintext_key_sha1.hex() == masterkey_sha1_hash

    @pytest.mark.asyncio
    async def test_decrypt_masterkey_file_with_backup_key_oldformat(self, get_file_path):
        """Test decrypting a domain masterkey file using backup key."""
        # Load the backup key from fixtures
        backupkey_file = get_file_path("old/dpapi_domain_backupkey.json")
        with open(backupkey_file) as f:
            backupkey_data = json.load(f)

        # Create DomainBackupKey from the fixture data
        backup_key = DomainBackupKey(
            guid=UUID(backupkey_data["domain_backupkey_guid"]),
            key_data=base64.b64decode(backupkey_data["domain_backupkey_b64"]),
            domain_controller=backupkey_data["domain_controller"],
        )

        # Load the domain masterkey file
        masterkey_file = MasterKeyFile.parse(get_file_path("old/ab998260-e99d-4871-8f4b-d922b2848ce6"))

        # Decrypt the masterkey
        decrypted_masterkey = backup_key.decrypt_masterkey_file(masterkey_file)

        # Verify decryption succeeded
        assert decrypted_masterkey is not None
        assert decrypted_masterkey.is_decrypted
        assert decrypted_masterkey.guid == masterkey_file.masterkey_guid
        assert decrypted_masterkey.plaintext_key is not None
        assert decrypted_masterkey.plaintext_key_sha1 is not None
        assert decrypted_masterkey.backup_key_guid == backup_key.guid
        assert len(decrypted_masterkey.plaintext_key_sha1) == 20  # SHA1 is 20 bytes

        assert (
            masterkey_file is not None
            and masterkey_file.master_key is not None
            and masterkey_file.domain_backup_key is not None
        )

        manager = DpapiManager(storage_backend="memory", auto_decrypt=True)
        await manager.add_domain_backup_key(backup_key)
        await manager.add_encrypted_masterkey(
            guid=masterkey_file.masterkey_guid,
            encrypted_key_usercred=masterkey_file.master_key,
            encrypted_key_backup=masterkey_file.domain_backup_key,
        )
        blob = Blob.parse(get_file_path("old/dpapi_blob.bin"))

        assert blob.masterkey_guid == masterkey_file.masterkey_guid

        await asyncio.sleep(0.5)  # Give auto-decryption a moment to complete

        decrypted = await manager.decrypt_blob(blob)
        assert decrypted == b"This is a test."  # Adjusted expected value

    def test_decrypt_masterkey_file_no_domain_key(self):
        """Test decrypting a masterkey file without domain backup key raises exception."""
        from uuid import uuid4

        # Create a backup key
        backup_key = DomainBackupKey(guid=uuid4(), key_data=b"fake_key_data")

        # Load the local masterkey file (no domain backup key)
        masterkey_file = MasterKeyFile.parse("tests/fixtures/masterkey_local.bin")

        # Should raise MasterKeyDecryptionError since no domain backup key in file
        with pytest.raises(MasterKeyDecryptionError, match="contains no domain backup key"):
            backup_key.decrypt_masterkey_file(masterkey_file)
