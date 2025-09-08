"""Tests for DPAPI core models."""

import base64
import json
from pathlib import Path
from uuid import UUID

import pytest
from nemesis_dpapi import Blob, DomainBackupKey, DpapiManager, MasterKeyFile
from nemesis_dpapi.core import DpapiSystemCredential, MasterKey, MasterKeyPolicy
from nemesis_dpapi.crypto import CredKey, CredKeyHashType, MasterKeyEncryptionKey

dpapi_system_secret_hex = "01000000dcfd03644f501805c189e15e9367b01415dea75a4e25d96d26879ded571f5d48a6887455d28f66f5"
dpapi_system_secret_bytes = bytes.fromhex(dpapi_system_secret_hex)
dpapi_system_machine_key_hex = "dcfd03644f501805c189e15e9367b01415dea75a"
dpapi_system_user_key_hex = "4e25d96d26879ded571f5d48a6887455d28f66f5"

system_masterkey_hex = "020000000000000000000000640064003200360066003800310061002d0034006500640039002d0034003900660064002d0038006200340035002d00340032003700320033006400380061006500300030003600000000000000000006000000b00000000000000090000000000000001400000000000000000000000000000002000000bd2a4e8a1f66c1c29d972ad32534a801401f00000e80000010660000a6fddbe74e2b8975fe896c075bee61c5aee3112b35abc39f96d8229b3c3afe92f9c1db1242edcb84ff61bc3c70f955e73d99b6c1adbc1c8d258a2afd55d553c485eeae7515552ce7805af784b9c02e7cc3dc7dac56fa8fa59f61ebb7f4ad0378ade2f6e456db662ba2ba38441e542c071a2a60aa179835a90eb1f16fa2057808731937b2c4eb30db2b1cee02fff052290200000014c3adfc8d44ee78b8a652bf98e840e8401f00000e80000010660000587695a3307eb92ce3a55de58fb2ee6eee3d8561bd18bea34d44d01b3dba8dea0036cdd5d882c412ce293a3c5316fe6b7e7e2eae7ec11c4d46bbb6654b3f89c77a38fc4d340ea0be7733385a2577fb5b3acdf22fbafc19b9f697f3fa50ba5f1a1d3407c51c0ae14aa8f394f5122def910300000000000000000000000000000000000000"
system_masterkey_bytes = bytes.fromhex(system_masterkey_hex)
system_masterkey_guid = UUID("dd26f81a-4ed9-49fd-8b45-42723d8ae006")
system_masterkey_plaintext_sha1 = "b848ddc68f5250e5977bc52fd9671811ba3bc3b1"

systemuser_masterkey_hex = "020000000000000000000000660062003100310039003000630031002d0031003200330064002d0034003500660038002d0039003500660034002d00330032006100650065003200380066006500320065006200000000000000000006000000b00000000000000090000000000000001400000000000000000000000000000002000000a4c506cfc4a0e9bcfeefcb8bfcc7f33e401f00000e80000010660000ab63a720b2e4c46bcbe3eb7c7259e7ad746d4e7f1566cdde0716e284a4b4a3f8851895a97db04c512963e11728d19db58873bc8dd8dae54937afbce49f9c723a5dbeba62c3a8b839410fa20a109a9de8857a6dd551052a201d9885365060323cd1d168715de699071e25e9f5c1ec11adf97160ef475d43ff0042c3f93ca47ff7756f335ec733acfc1b522afbeae07ac802000000732740ced42b4ebb05f8273b2f55f317401f00000e800000106600009451eb3cb464cd77ba53c19c792793ce19b7e7e9f1bc6512396b9f3325753741d4076b820e591b4a60418d1b6c6e15b6f30be25026b0ceceb9957e6b46ff5eb173c6642a83dd7bae6a7e5db7332ecbe1c13b0b88cf268ec479a351c0c37c8d425d61f61907b0e9658c832e397dfd67640300000000000000000000000000000000000000"
systemuser_masterkey_bytes = bytes.fromhex(systemuser_masterkey_hex)
systemuser_masterkey_guid = UUID("fb1190c1-123d-45f8-95f4-32aee28fe2eb")
systemuser_masterkey_plaintext_sha1 = "8a6f191d551750fa51324a6b8f3afc7086658888"


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
        backupkey_file = get_file_path("old_format/dpapi_domain_backupkey.json")
        masterkey_file = MasterKeyFile.parse(get_file_path("old_format/ab998260-e99d-4871-8f4b-d922b2848ce6"))
        blob = Blob.parse(get_file_path("old_format/dpapi_blob.bin"))

        with open(backupkey_file) as f:
            backupkey_data = json.load(f)

        # Create DomainBackupKey from the fixture data
        backup_key = DomainBackupKey(
            guid=UUID(backupkey_data["domain_backupkey_guid"]),
            key_data=base64.b64decode(backupkey_data["domain_backupkey_b64"]),
            domain_controller=backupkey_data["domain_controller"],
        )

        # Load the domain masterkey file

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

        await manager.add_masterkey(
            MasterKey(
                guid=decrypted_masterkey.guid,
                plaintext_key=decrypted_masterkey.plaintext_key,
                plaintext_key_sha1=decrypted_masterkey.plaintext_key_sha1,
            )
        )

        assert blob.masterkey_guid == masterkey_file.masterkey_guid

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
        with pytest.raises(ValueError, match="contains no domain backup key"):
            backup_key.decrypt_masterkey_file(masterkey_file)


class TestDpapiSystemSecret:
    """Tests for DpapiSystemSecret class."""

    def test_from_bytes_valid_40_bytes(self):
        """Test creating DpapiSystemSecret from valid 40-byte data."""
        # Create test data: 20 bytes user key + 20 bytes machine key
        user_key_data = b"user_key_12345678901"  # 20 bytes
        machine_key_data = b"mach_key_12345678901"  # 20 bytes
        dpapi_system_data = user_key_data + machine_key_data

        secret = DpapiSystemCredential.from_bytes(dpapi_system_data)

        assert secret.user_key == user_key_data
        assert secret.machine_key == machine_key_data

    def test_direct_creation_with_bytes(self):
        """Test creating DpapiSystemSecret directly with bytes."""
        # Create test data: 20 bytes user key + 20 bytes machine key
        user_key_data = b"user_key_12345678901"  # 20 bytes
        machine_key_data = b"mach_key_12345678901"  # 20 bytes

        # Test by creating instance directly with bytes
        secret = DpapiSystemCredential(
            user_key=user_key_data,
            machine_key=machine_key_data,
        )

        assert secret.user_key == user_key_data
        assert secret.machine_key == machine_key_data

    def test_from_bytes_invalid_length_short(self):
        """Test from_bytes with data too short raises ValueError."""
        short_data = b"too_short"  # Only 9 bytes

        with pytest.raises(ValueError, match="DPAPI_SYSTEM must be exactly 40 bytes, got 9"):
            DpapiSystemCredential.from_bytes(short_data)

    def test_from_bytes_invalid_length_long(self):
        """Test from_bytes with data too long raises ValueError."""
        long_data = b"a" * 50  # 50 bytes

        with pytest.raises(ValueError, match="DPAPI_SYSTEM must be exactly 40 bytes, got 50"):
            DpapiSystemCredential.from_bytes(long_data)

    def test_from_lsa_secret_valid_structure(self):
        """Test creating DpapiSystemSecret from valid LSA secret structure."""

        secret = DpapiSystemCredential.from_lsa_secret(dpapi_system_secret_hex)

        assert secret.user_key == bytes.fromhex(dpapi_system_user_key_hex)
        assert secret.machine_key == bytes.fromhex(dpapi_system_machine_key_hex)

    def test_from_lsa_secret_and_direct_creation(self):
        """Test creating DpapiSystemSecret from LSA secret and direct instantiation."""
        import struct

        # Create valid LSA secret structure
        version = 1
        machine_key = b"mach_key_12345678901"  # 20 bytes
        user_key = b"user_key_12345678901"  # 20 bytes

        lsa_secret_data = struct.pack("<L20s20s", version, machine_key, user_key)

        # First parse with bytes to get the expected values
        secret_from_bytes = DpapiSystemCredential.from_lsa_secret(lsa_secret_data)

        # Test by creating instance directly with bytes
        secret_from_hex = DpapiSystemCredential(
            user_key=user_key,
            machine_key=machine_key,
        )

        assert secret_from_hex.user_key == user_key
        assert secret_from_hex.machine_key == machine_key
        assert secret_from_hex.user_key == secret_from_bytes.user_key
        assert secret_from_hex.machine_key == secret_from_bytes.machine_key

    def test_from_lsa_secret_too_small(self):
        """Test from_lsa_secret with data too small raises ValueError."""
        small_data = b"too_small"  # Only 9 bytes

        with pytest.raises(ValueError, match="Incorrect LSA secret size, expected at least 44 bytes, got 9"):
            DpapiSystemCredential.from_lsa_secret(small_data)

    def test_from_lsa_secret_invalid_version(self):
        """Test from_lsa_secret with invalid version raises ValueError."""
        import struct

        # Create LSA secret with invalid version
        version = 0  # Should be 1
        machine_key = b"mach_key_12345678901"  # 20 bytes
        user_key = b"user_key_12345678901"  # 20 bytes

        lsa_secret_data = struct.pack("<L20s20s", version, machine_key, user_key)

        with pytest.raises(ValueError, match="Unexpected LSA secret version: 0, expected 1"):
            DpapiSystemCredential.from_lsa_secret(lsa_secret_data)

    def test_from_lsa_secret_zero_machine_key_accepted(self):
        """Test from_lsa_secret with zero-filled machine key is accepted."""
        import struct

        # Create LSA secret with zero-filled machine key
        version = 1
        machine_key = b"\x00" * 20  # All zeros - still valid bytes
        user_key = b"user_key_12345678901"  # 20 bytes

        lsa_secret_data = struct.pack("<L20s20s", version, machine_key, user_key)

        # Zero-filled keys are valid - they're still 20 bytes
        secret = DpapiSystemCredential.from_lsa_secret(lsa_secret_data)

        assert secret.user_key == user_key
        assert secret.machine_key == machine_key

    def test_from_lsa_secret_zero_user_key_accepted(self):
        """Test from_lsa_secret with zero-filled user key is accepted."""
        import struct

        # Create LSA secret with zero-filled user key
        version = 1
        machine_key = b"mach_key_12345678901"  # 20 bytes
        user_key = b"\x00" * 20  # All zeros - still valid bytes

        lsa_secret_data = struct.pack("<L20s20s", version, machine_key, user_key)

        # Zero-filled keys are valid - they're still 20 bytes
        secret = DpapiSystemCredential.from_lsa_secret(lsa_secret_data)

        assert secret.user_key == user_key
        assert secret.machine_key == machine_key

    def test_from_lsa_secret_malformed_struct(self):
        """Test from_lsa_secret with malformed structure raises ValueError."""
        malformed_data = b"malformed_struct_data_not_enough_bytes"

        with pytest.raises(ValueError, match="Incorrect LSA secret size"):
            DpapiSystemCredential.from_lsa_secret(malformed_data)

    def test_from_lsa_secret_exact_size(self):
        """Test from_lsa_secret with exactly 44 bytes works correctly."""
        import struct

        # Create exactly 44 byte LSA secret structure
        version = 1
        machine_key = b"1234567890abcdefghij"  # 20 bytes
        user_key = b"ABCDEFGHIJ0987654321"  # 20 bytes

        lsa_secret_data = struct.pack("<L20s20s", version, machine_key, user_key)
        assert len(lsa_secret_data) == 44

        secret = DpapiSystemCredential.from_lsa_secret(lsa_secret_data)

        assert secret.user_key == user_key
        assert secret.machine_key == machine_key

    def test_from_lsa_secret_extra_data_rejected(self):
        """Test from_lsa_secret rejects data with extra bytes beyond the structure."""
        import struct

        # Create LSA secret structure with extra data
        version = 0
        machine_key = b"mach_key_12345678901"  # 20 bytes
        user_key = b"user_key_12345678901"  # 20 bytes

        lsa_secret_data = struct.pack("<L20s20s", version, machine_key, user_key)
        lsa_secret_data += b"extra_data_that_should_be_ignored"

        # Should raise ValueError because length is not exactly 44 bytes
        with pytest.raises(ValueError, match="Incorrect LSA secret size, expected at least 44 bytes, got 77"):
            DpapiSystemCredential.from_lsa_secret(lsa_secret_data)


class TestMasterKey:
    """Tests for MasterKey class."""

    def test_masterkey_decrypt_with_password(self):
        """Test MasterKey.decrypt using NTLM credential key with real masterkey data."""
        password = "Qwerty12345"
        user_sid = "S-1-5-21-3821320868-1508310791-3575676346-1103"

        expected_masterkey_bytes = bytes.fromhex(
            "36BD60CB9E7E52433169DB00E93ED0A82D3C30C65D948BD8596FB32C267671020B02026B0AE03479DD18374ADBDD7658F45CCE6ED2A45319EFF7A96C411C85F5"
        )
        expected_masterkey_sha1_bytes = bytes.fromhex("17FD87F91D25A18ABD9BCD66B6D9F3C6BFC16778")

        masterkey_file = MasterKeyFile.parse(Path("tests/fixtures/masterkey_domain.bin"))

        masterkey = MasterKey(
            guid=masterkey_file.masterkey_guid,
            encrypted_key_usercred=masterkey_file.master_key,
        )

        cred_key = CredKey.from_password(password, CredKeyHashType.PBKDF2, user_sid)
        mk_encryption_key = MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)
        decrypted_masterkey = masterkey.decrypt(mk_encryption_key)

        assert decrypted_masterkey is not None
        assert decrypted_masterkey.is_decrypted
        assert decrypted_masterkey.guid == masterkey_file.masterkey_guid
        assert decrypted_masterkey.plaintext_key is not None
        assert decrypted_masterkey.plaintext_key_sha1 is not None
        assert len(decrypted_masterkey.plaintext_key_sha1) == 20
        assert decrypted_masterkey.plaintext_key.hex().upper() == expected_masterkey_bytes.hex().upper()
        assert decrypted_masterkey.plaintext_key_sha1.hex().upper() == expected_masterkey_sha1_bytes.hex().upper()

    def test_masterkey_decrypt_with_system_credential(self, get_file_path):
        """Test MasterKey.decrypt using NTLM credential key with real masterkey data."""

        masterkey_file = MasterKeyFile.parse(get_file_path("masterkey_system.bin"))
        masterkey = MasterKey(
            guid=masterkey_file.masterkey_guid,
            encrypted_key_usercred=masterkey_file.master_key,
        )

        mk_encryption_key = MasterKeyEncryptionKey.from_dpapi_system_cred(bytes.fromhex(dpapi_system_machine_key_hex))
        decrypted_masterkey = masterkey.decrypt(mk_encryption_key)

        assert decrypted_masterkey is not None
        assert decrypted_masterkey.is_decrypted
        assert decrypted_masterkey.guid == system_masterkey_guid
        assert decrypted_masterkey.plaintext_key is not None
        assert decrypted_masterkey.plaintext_key_sha1 is not None
        assert len(decrypted_masterkey.plaintext_key_sha1) == 20  # SHA1 is 20 bytes
        assert decrypted_masterkey.plaintext_key_sha1 == bytes.fromhex(system_masterkey_plaintext_sha1)

    def test_masterkey_decrypt_with_systemuser_credential(self, get_file_path):
        """Test MasterKey.decrypt using NTLM credential key with real masterkey data."""

        masterkey_file = MasterKeyFile.parse(get_file_path("masterkey_systemuser.bin"))
        masterkey = MasterKey(
            guid=masterkey_file.masterkey_guid,
            encrypted_key_usercred=masterkey_file.master_key,
        )

        mk_encryption_key = MasterKeyEncryptionKey.from_dpapi_system_cred(bytes.fromhex(dpapi_system_user_key_hex))
        decrypted_masterkey = masterkey.decrypt(mk_encryption_key)

        assert decrypted_masterkey is not None
        assert decrypted_masterkey.is_decrypted
        assert decrypted_masterkey.guid == systemuser_masterkey_guid
        assert decrypted_masterkey.plaintext_key is not None
        assert decrypted_masterkey.plaintext_key_sha1 is not None
        assert len(decrypted_masterkey.plaintext_key_sha1) == 20  # SHA1 is 20 bytes
        assert decrypted_masterkey.plaintext_key_sha1 == bytes.fromhex(systemuser_masterkey_plaintext_sha1)

    def test_masterkey_decrypt_no_encrypted_key_raises_error(self):
        """Test MasterKey.decrypt raises ValueError when no encrypted key is available."""
        from uuid import uuid4

        # Create MasterKey without encrypted_key_usercred
        masterkey = MasterKey(guid=uuid4())

        # Create dummy encryption key
        cred_key = CredKey.from_password("dummy", CredKeyHashType.NTLM)
        mk_encryption_key = MasterKeyEncryptionKey.from_cred_key(cred_key, "S-1-5-21-1-1-1-1000")

        # Should raise ValueError
        with pytest.raises(ValueError, match="No encrypted user credential key available for decryption"):
            masterkey.decrypt(mk_encryption_key)
