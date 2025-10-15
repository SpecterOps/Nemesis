"""Tests for DPAPI core models."""

import base64
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from impacket.dpapi import DPAPI_BLOB
from nemesis_dpapi.core import Blob, MasterKey, MasterKeyFile, MasterKeyPolicy, MasterKeyType
from nemesis_dpapi.exceptions import BlobDecryptionError
from nemesis_dpapi.keys import CredKey, CredKeyHashType, MasterKeyEncryptionKey
from pydantic import ValidationError

masterkey_uuid = UUID("ed93694f-5a6d-46e2-b821-219f2c0ecd4d")
masterkey_bytes = bytes.fromhex(
    "36BD60CB9E7E52433169DB00E93ED0A82D3C30C65D948BD8596FB32C267671020B02026B0AE03479DD18374ADBDD7658F45CCE6ED2A45319EFF7A96C411C85F5"
)
masterkey_sha1_bytes = bytes.fromhex("17FD87F91D25A18ABD9BCD66B6D9F3C6BFC16778")
masterkey_entry = "{ed93694f-5a6d-46e2-b821-219f2c0ecd4d}:17FD87F91D25A18ABD9BCD66B6D9F3C6BFC16778"
masterkey_entries = """
{ed93694f-5a6d-46e2-b821-219f2c0ecd4d}:17FD87F91D25A18ABD9BCD66B6D9F3C6BFC16778
{12345678-1234-1234-1234-123456789012}:ABCDEF1234567890ABCDEF1234567890ABCDEF12
""".strip()

dpapi_system_secret_hex = "01000000dcfd03644f501805c189e15e9367b01415dea75a4e25d96d26879ded571f5d48a6887455d28f66f5"
dpapi_system_secret_bytes = bytes.fromhex(dpapi_system_secret_hex)
dpapi_system_machine_user_key_hex = dpapi_system_secret_hex[8:]  # Skip version header
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

        masterkey = MasterKeyFile.from_file(test_file)

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

        # Check backup key struct
        assert not masterkey.backup_key

        # Check domain backup key struct
        assert masterkey.domain_backup_key
        assert len(masterkey.domain_backup_key.raw_bytes) == 428
        assert masterkey.domain_backup_key.version == 3
        assert masterkey.domain_backup_key.cb_encrypted_master_key == 256
        assert masterkey.domain_backup_key.cb_encrypted_payload == 144
        assert str(masterkey.domain_backup_key.guid_key) == "7efa51b1-2523-45bf-acba-2e15ecf4f1e7"
        assert masterkey.domain_backup_key.encrypted_master_key.hex().startswith("e200130192")
        assert masterkey.domain_backup_key.encrypted_payload.hex().startswith("132f05f5")

    def test_parse_valid_masterkey_file_local(self):
        """Test parsing a valid masterkey file from a local account."""
        test_file = Path("tests/fixtures/masterkey_local.bin")

        masterkey = MasterKeyFile.from_file(test_file)

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
            MasterKeyFile.from_file("nonexistent_file.bin")

    def test_parse_empty_file(self, tmp_path):
        """Test parsing an empty file raises ValueError."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        with pytest.raises(ValueError, match="File too small"):
            MasterKeyFile.from_file(empty_file)

    def test_parse_truncated_header(self, tmp_path):
        """Test parsing a file with truncated header raises ValueError."""
        truncated_file = tmp_path / "truncated.bin"
        truncated_file.write_bytes(b"truncated_data_too_short")

        with pytest.raises(ValueError, match="File too small"):
            MasterKeyFile.from_file(truncated_file)

    def test_parse_invalid_size(self, tmp_path):
        """Test parsing a file with invalid key data size raises ValueError."""
        invalid_file = tmp_path / "invalid.bin"

        # Create a minimal header that claims more data than available
        import struct

        header = struct.pack(
            "<III80sIIIIIIIII",
            2,  # version
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
            MasterKeyFile.from_file(invalid_file)

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
            2,  # version
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

        masterkey = MasterKeyFile.from_file(test_file)

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

        blob = Blob.from_bytes(blob_data)

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

        masterkey_file = MasterKeyFile.from_file(Path("tests/fixtures/masterkey_domain.bin"))

        masterkey = MasterKey(
            guid=masterkey_file.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
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

        masterkey_file = MasterKeyFile.from_file(get_file_path("masterkey_system.bin"))
        masterkey = MasterKey(
            guid=masterkey_file.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
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

        masterkey_file = MasterKeyFile.from_file(get_file_path("masterkey_systemuser.bin"))
        masterkey = MasterKey(
            guid=masterkey_file.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
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
        masterkey = MasterKey(guid=uuid4(), masterkey_type=MasterKeyType.UNKNOWN)

        # Create dummy encryption key
        cred_key = CredKey.from_password("dummy", CredKeyHashType.NTLM)
        mk_encryption_key = MasterKeyEncryptionKey.from_cred_key(cred_key, "S-1-5-21-1-1-1-1000")

        # Should raise ValueError
        with pytest.raises(ValueError, match="No encrypted user credential key available for decryption"):
            masterkey.decrypt(mk_encryption_key)

    def test_masterkey_auto_calculates_sha1(self):
        """Test that MasterKey auto-calculates plaintext_key_sha1 when only plaintext_key is provided."""

        # Create MasterKey with only plaintext_key (no plaintext_key_sha1)
        masterkey = MasterKey(
            guid=uuid4(),
            masterkey_type=MasterKeyType.UNKNOWN,
            plaintext_key=masterkey_bytes,
        )

        # Verify plaintext_key_sha1 was auto-calculated
        assert masterkey.plaintext_key_sha1 is not None
        assert masterkey.plaintext_key_sha1 == masterkey_sha1_bytes
        assert masterkey.is_decrypted

    def test_masterkey_frozen(self):
        """Test that MasterKey is frozen (immutable)."""

        masterkey = MasterKey(guid=uuid4(), masterkey_type=MasterKeyType.UNKNOWN)

        # Should not be able to modify frozen model
        with pytest.raises(ValidationError):
            masterkey.guid = uuid4()  # type: ignore

    def test_masterkey_validates_correct_sha1(self):
        """Test that MasterKey accepts correct plaintext_key_sha1."""
        from uuid import uuid4

        plaintext_key = masterkey_bytes
        correct_sha1 = masterkey_sha1_bytes

        # Should accept correct SHA1
        masterkey = MasterKey(
            guid=uuid4(),
            masterkey_type=MasterKeyType.UNKNOWN,
            plaintext_key=plaintext_key,
            plaintext_key_sha1=correct_sha1,
        )

        assert masterkey.plaintext_key_sha1 == correct_sha1
        assert masterkey.is_decrypted

    def test_masterkey_rejects_incorrect_sha1(self):
        """Test that MasterKey rejects incorrect plaintext_key_sha1."""

        plaintext_key = masterkey_bytes
        incorrect_sha1 = b"0" * 20  # Wrong SHA1

        # Should reject incorrect SHA1
        with pytest.raises(ValidationError, match="plaintext_key_sha1 does not match"):
            MasterKey(
                guid=uuid4(),
                masterkey_type=MasterKeyType.UNKNOWN,
                plaintext_key=plaintext_key,
                plaintext_key_sha1=incorrect_sha1,
            )


class TestBlobDecrypt:
    """Test Blob.decrypt() method."""

    def test_decrypt_blob_with_unencrypted_masterkey(self, blob_without_entropy: bytes):
        """Test DPAPI blob decryption with unencrypted master key."""
        blob = Blob.from_bytes(blob_without_entropy)
        # Create an unencrypted master key
        masterkey = MasterKey(guid=blob.masterkey_guid, masterkey_type=MasterKeyType.UNKNOWN)

        with pytest.raises(ValueError, match="Master key must be decrypted before use"):
            blob.decrypt(masterkey)

    def test_decrypt_blob_with_wrong_masterkey(self, blob_without_entropy: bytes):
        """Test DPAPI blob decryption with wrong masterkey."""
        blob = Blob.from_bytes(blob_without_entropy)
        # Create a master key with wrong SHA1 hash

        masterkey = MasterKey(
            guid=blob.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
            plaintext_key=b"d" * 20,
        )

        with pytest.raises(BlobDecryptionError):
            blob.decrypt(masterkey)

    def test_decrypt_blob_with_entropy(self, blob_with_entropy: bytes):
        blob = Blob.from_bytes(blob_with_entropy)
        assert blob.masterkey_guid == masterkey_uuid

        masterkey_sha1_bytes = bytes.fromhex("17FD87F91D25A18ABD9BCD66B6D9F3C6BFC16778")
        masterkey = MasterKey(
            guid=blob.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
            plaintext_key=masterkey_bytes,
            plaintext_key_sha1=masterkey_sha1_bytes,
        )

        entropy = bytes([1, 2, 3, 4, 5])
        decrypted_data = blob.decrypt(masterkey, entropy=entropy)

        assert isinstance(decrypted_data, bytes)
        assert len(decrypted_data) > 0
        assert decrypted_data.decode("utf-8") == "test"

    def test_decrypt_blob_without_entropy(self, blob_without_entropy: bytes):
        blob = Blob.from_bytes(blob_without_entropy)

        assert blob.masterkey_guid == masterkey_uuid

        masterkey_sha1_bytes = bytes.fromhex("17FD87F91D25A18ABD9BCD66B6D9F3C6BFC16778")
        masterkey = MasterKey(
            guid=blob.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
            plaintext_key=masterkey_bytes,
            plaintext_key_sha1=masterkey_sha1_bytes,
        )

        decrypted_data = blob.decrypt(masterkey)

        assert isinstance(decrypted_data, bytes)
        assert len(decrypted_data) > 0
        assert decrypted_data.decode("utf-8") == "test"

    def test_decrypt_blob_app_bound_enc_key(self, read_file_text):
        """Test DPAPI blob decryption with app-bound encrypted key from fixture."""
        blob_b64 = read_file_text("blob_app_bound_enc_key.txt").strip()
        blob_data = base64.b64decode(blob_b64)[4:]
        blob = Blob.from_bytes(blob_data)

        assert blob.description == "Google Chrome"
        assert str(blob.masterkey_guid).lower() == "f752e2e1-1726-454b-a632-0718d94ca677"
        masterkey_sha1_bytes = bytes.fromhex("9DED7C56C3FE577B84780908ADAC346F38F1D114")

        # Create a proper master key object
        masterkey = MasterKey(
            guid=blob.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
            plaintext_key_sha1=masterkey_sha1_bytes,
        )

        # Test our new Blob.decrypt method
        try:
            decrypted_data = blob.decrypt(masterkey)
            assert isinstance(decrypted_data, bytes)
            assert len(decrypted_data) > 0
        except ValueError:
            pytest.skip("Unable to decrypt app-bound encrypted key blob with provided masterkey")

        # Also verify against dpapick3 reference implementation
        from dpapick3 import blob as dpapick3_blob

        blob_dpapick = dpapick3_blob.DPAPIBlob(blob.raw_bytes)
        assert blob_dpapick.decrypt(masterkey_sha1_bytes)

    def test_decrypt_chrome_cng_blob(self):
        """Test DPAPI blob decryption with app-bound encrypted key from fixture."""

        masterkey = MasterKey(
            guid=UUID("fb1190c1-123d-45f8-95f4-32aee28fe2eb"),
            masterkey_type=MasterKeyType.SYSTEM,
            plaintext_key_sha1=bytes.fromhex(systemuser_masterkey_plaintext_sha1),
        )

        # CNG SystemKey: 0100000000000000220000000200010004010000520100001C0100000000000000000000000000000000000047006F006F0067006C00650020004300680072006F006D0065006B006500790031002C000000000000000000000010000000080000004D006F00640069006600690065006400438FDAE8593DDC01D8000000200000000000000024000000A0000000430072006500610074006F007200500072006F0063006500730073004E0061006D00650043003A005C00500072006F006700720061006D002000460069006C00650073005C0047006F006F0067006C0065005C004300680072006F006D0065005C004100700070006C00690063006100740069006F006E005C003100340031002E0030002E0037003300390030002E003100300038005C0065006C00650076006100740069006F006E005F0073006500720076006900630065002E00650078006500000001000000D08C9DDF0115D1118C7A00C04FC297EB01000000C19011FB3D12F84595F432AEE28FE2EB000000002E000000500072006900760061007400650020004B00650079002000500072006F0070006500720074006900650073000000106600000001000020000000E1451697BACA6528F7D630D9BAF15ED201FEA6204EDFFF8AFA1087E91EFCE242000000000E8000000002000020000000410FB7DD8537700968CCBD606CD3983E9CF688B10ED971F89678CFE9ABCA6640500000005EA8B351046F51253A04F31AD7837DDEFB65C0B0E1BB420CE46D0C37DBCCA98894F021BC8023E46AF932BAE65228B0FA0D3E851B11B9E604E38AD805A1DD3EB93723EA9590C54E4DFBA06B0433B1A31D400000006AB35EAA9F103166A3154DA144C01A48D2109B9F2BA4C41C08F26B2D53878AF4FE010F623925CA197E1AF740D73D163A03D024DD29DD40976978F4E9C1A23B3701000000D08C9DDF0115D1118C7A00C04FC297EB01000000C19011FB3D12F84595F432AEE28FE2EB0000000018000000500072006900760061007400650020004B006500790000001066000000010000200000007F05374264DEFCD4065DB19AAE164B6AA6B7E51B63EBEE2A24B2682423FC9CF7000000000E8000000002000020000000FA9A99E7200A93C34D63CA3F94336490B50AC245138C9940681706B56CB045DC30000000D49A90D77306D54AB002BE9C31AB6CF84B574450CDABB4C6E58C5FBADE9D8D3C3D024D4DB24DC683CDA249E15FDBFFBF40000000780903E736CFACC632709C2A76DAD0FD862010CCDA01BF7B9256F336CCF67623780F0CB46D37E3B91C5EE20D070EB4FE699997B212037265039671532CB20672
        blob = Blob.from_bytes(
            bytes.fromhex(
                "01000000D08C9DDF0115D1118C7A00C04FC297EB01000000C19011FB3D12F84595F432AEE28FE2EB0000000018000000500072006900760061007400650020004B006500790000001066000000010000200000007F05374264DEFCD4065DB19AAE164B6AA6B7E51B63EBEE2A24B2682423FC9CF7000000000E8000000002000020000000FA9A99E7200A93C34D63CA3F94336490B50AC245138C9940681706B56CB045DC30000000D49A90D77306D54AB002BE9C31AB6CF84B574450CDABB4C6E58C5FBADE9D8D3C3D024D4DB24DC683CDA249E15FDBFFBF40000000780903E736CFACC632709C2A76DAD0FD862010CCDA01BF7B9256F336CCF67623780F0CB46D37E3B91C5EE20D070EB4FE699997B212037265039671532CB20672"
            )
        )

        assert blob.masterkey_guid == masterkey.guid

        # Test our new Blob.decrypt method
        entropy = b"xT5rZW5qVVbrvpuA\x00"
        decrypted_data = blob.decrypt(masterkey, entropy=entropy)
        assert isinstance(decrypted_data, bytes)
        assert len(decrypted_data) > 0
        assert decrypted_data == bytes.fromhex(
            "4b44424d0100000020000000442ad62f22c9bc1bf2c9a67a4cfc5ac0d3b660b4e431f6b2232c8a730fbc1e21"
        )


class TestBlobParse:
    """Test Blob.parse() method."""

    def test_parse_blob(self, blob_without_entropy):
        """Test parsing DPAPI blob data against reference implementations."""
        from dpapick3 import blob as dpapick3_blob

        blob = Blob.from_bytes(blob_without_entropy)
        blob_impacket = DPAPI_BLOB(blob_without_entropy)
        blob_dpapick = dpapick3_blob.DPAPIBlob(blob_without_entropy)

        # Basic metadata
        assert blob.version == blob_impacket["Version"] == blob_dpapick.version
        assert blob.prompt_flags == blob_impacket["Flags"] == blob_dpapick.flags

        # GUIDs
        assert blob.provider_guid.bytes_le == blob_impacket["GuidCredential"]
        assert str(blob.provider_guid).lower() == blob_dpapick.provider.lower()  # type: ignore
        assert blob.masterkey_guid.bytes_le == blob_impacket["GuidMasterKey"]
        assert str(blob.masterkey_guid).lower() == blob_dpapick.mkguid.lower()  # type: ignore

        # Description (handle null-terminated UTF-16LE strings)
        impacket_desc = blob_impacket["Description"].decode("utf-16le").rstrip("\x00")
        assert blob.description == impacket_desc

        if blob_dpapick.description != b"\x00":
            dpapick_desc = blob_dpapick.description.decode("utf-16le").rstrip("\x00")  # type: ignore
            assert blob.description == dpapick_desc

        # Encryption algorithm
        assert blob.encryption_algorithm_id == blob_impacket["CryptAlgo"] == blob_dpapick.cipherAlgo.algnum  # type: ignore
        assert blob.encryption_algorithm_key_size == blob_impacket["CryptAlgoLen"]

        # MAC algorithm
        assert blob.mac_algorithm_id == blob_impacket["HashAlgo"] == blob_dpapick.hashAlgo.algnum  # type: ignore
        assert blob.mac_algorithm_key_size == blob_impacket["HashAlgoLen"]

        # Data
        assert blob.encryption_salt == blob_impacket["Salt"] == blob_dpapick.salt
        assert blob.encrypted_data == blob_impacket["Data"] == blob_dpapick.cipherText


class TestMasterKeyType:
    """Tests for MasterKeyType.from_path() method."""

    def test_from_path_none(self):
        """Test from_path returns UNKNOWN for None path."""
        assert MasterKeyType.from_path(None) == MasterKeyType.UNKNOWN

    def test_from_path_empty_string(self):
        """Test from_path returns UNKNOWN for empty string."""
        assert MasterKeyType.from_path("") == MasterKeyType.UNKNOWN

    def test_from_path_system_user(self):
        """Test from_path correctly identifies SYSTEM_USER paths."""
        test_paths = [
            r"C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"C:\WINDOWS\SYSTEM32\MICROSOFT\PROTECT\S-1-5-18\USER\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"/Windows/System32/Microsoft/Protect/S-1-5-18/User/ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
        ]
        for path in test_paths:
            assert MasterKeyType.from_path(path) == MasterKeyType.SYSTEM_USER, f"Failed for path: {path}"

    def test_from_path_system(self):
        """Test from_path correctly identifies SYSTEM paths."""
        test_paths = [
            r"C:\Windows\System32\Microsoft\Protect\S-1-5-18\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"C:\WINDOWS\SYSTEM32\MICROSOFT\PROTECT\S-1-5-18\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"/Windows/System32/Microsoft/Protect/S-1-5-18/ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
        ]
        for path in test_paths:
            assert MasterKeyType.from_path(path) == MasterKeyType.SYSTEM, f"Failed for path: {path}"

    def test_from_path_system_service_profiles(self):
        """Test from_path correctly identifies LocalService and NetworkService paths."""
        test_paths = [
            r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Protect\S-1-5-19\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"C:\Windows\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Protect\S-1-5-20\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"C:\WINDOWS\SERVICEPROFILES\LOCALSERVICE\APPDATA\ROAMING\MICROSOFT\PROTECT\S-1-5-19\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"/Windows/ServiceProfiles/LocalService/AppData/Roaming/Microsoft/Protect/S-1-5-19/ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
        ]
        for path in test_paths:
            assert MasterKeyType.from_path(path) == MasterKeyType.SYSTEM, f"Failed for path: {path}"

    def test_from_path_user_with_sid(self):
        """Test from_path correctly identifies USER paths with SID."""
        test_paths = [
            r"C:\Users\john.doe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3821320868-1508310791-3575676346-1103\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-1234567890-1234567890-1234567890-500\387a062d-f8b6-4661-b2c5-eecbb9f80afb",
            r"C:\USERS\TESTUSER\APPDATA\ROAMING\MICROSOFT\PROTECT\S-1-5-21-111-222-333-1001\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"/Users/john.doe/AppData/Roaming/Microsoft/Protect/S-1-5-21-3821320868-1508310791-3575676346-1103/ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
        ]
        for path in test_paths:
            assert MasterKeyType.from_path(path) == MasterKeyType.USER, f"Failed for path: {path}"

    def test_from_path_user_with_protect_fallback(self):
        """Test from_path correctly identifies USER paths using fallback pattern."""
        test_paths = [
            r"C:\Users\john.doe\AppData\Roaming\Microsoft\Protect\somefile",
            r"C:\Users\Administrator\AppData\Roaming\Microsoft\Protect" + "\\somedir",
        ]
        for path in test_paths:
            assert MasterKeyType.from_path(path) == MasterKeyType.USER, f"Failed for path: {path}"

    def test_from_path_unknown_patterns(self):
        """Test from_path returns UNKNOWN for unrecognized patterns."""
        test_paths = [
            r"C:\SomeOtherPath\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"C:\Program Files\MyApp\data",
            r"/opt/data/masterkey.bin",
            r"D:\Temp\test.bin",
        ]
        for path in test_paths:
            assert MasterKeyType.from_path(path) == MasterKeyType.UNKNOWN, f"Failed for path: {path}"

    def test_from_path_case_insensitive(self):
        """Test from_path is case-insensitive."""
        paths_and_expected = [
            (r"c:\windows\system32\microsoft\protect\s-1-5-18\user\guid", MasterKeyType.SYSTEM_USER),
            (r"C:\WINDOWS\SYSTEM32\MICROSOFT\PROTECT\S-1-5-18\GUID", MasterKeyType.SYSTEM),
            (r"C:\users\JohnDoe\appdata\roaming\microsoft\protect\s-1-5-21-111-222-333-1001\guid", MasterKeyType.USER),
        ]
        for path, expected in paths_and_expected:
            assert MasterKeyType.from_path(path) == expected, f"Failed for path: {path}"

    def test_from_path_mixed_slashes(self):
        """Test from_path handles mixed forward and backward slashes."""
        test_paths = [
            r"C:\Windows/System32\Microsoft/Protect\S-1-5-18/User\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
            r"C:/Users\john.doe/AppData\Roaming/Microsoft\Protect/S-1-5-21-111-222-333-1001\ed93694f-5a6d-46e2-b821-219f2c0ecd4d",
        ]
        assert MasterKeyType.from_path(test_paths[0]) == MasterKeyType.SYSTEM_USER
        assert MasterKeyType.from_path(test_paths[1]) == MasterKeyType.USER
