"""Tests for DPAPI cryptographic operations."""

import base64
import json
from unittest.mock import PropertyMock, patch
from uuid import UUID

import pytest
from nemesis_dpapi.core import Blob, MasterKey, MasterKeyFile
from nemesis_dpapi.keys import (
    CredKey,
    CredKeyHashType,
    DomainBackupKey,
    DpapiSystemCredential,
    MasterKeyEncryptionKey,
    NtlmHash,
    Password,
    Pbkdf2Hash,
    Sha1Hash,
    _derive_secure_cred_key,
)
from nemesis_dpapi.manager import DpapiManager

password = "Qwerty12345"
ntlm_hash = "abd9ffb762c86b26ef4ce5c81b0dd37f"
ntlm_bytes = bytes.fromhex(ntlm_hash)
user_sid = "S-1-5-21-3821320868-1508310791-3575676346-1103"
user_sid_bytes = user_sid.encode("utf-16le")

credkey_ntlm_hash = ntlm_hash
credkey_sha1_hash = "15056cbc481efd37bba0e97e9c28493a40cf8745"
credkey_pbkdf2_hash = "775ec403415b49002386ea8e477346cd"

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


class TestPassword:
    """Test Password model."""

    def test_valid_password(self):
        """Test creating valid password."""
        password = Password(value="secret123")
        assert password.value == "secret123"

    def test_empty_password_raises_error(self):
        """Test empty password raises validation error."""
        with pytest.raises(ValueError, match="Password value cannot be empty"):
            Password(value="")

    def test_none_password_raises_error(self):
        """Test None password raises validation error."""
        with pytest.raises(ValueError):
            Password(value=None)  # type: ignore


class TestNtlmHash:
    """Test NtlmHash model."""

    def test_valid_ntlm_hash(self):
        """Test creating valid NTLM hash."""
        hash_bytes = b"a" * 16  # 16 bytes
        ntlm_hash = NtlmHash(value=hash_bytes)
        assert ntlm_hash.value == hash_bytes

    def test_invalid_length_raises_error(self):
        """Test invalid length raises validation error."""
        with pytest.raises(ValueError, match="NTLM hash must be exactly 16 bytes"):
            NtlmHash(value=b"a" * 15)

        with pytest.raises(ValueError, match="NTLM hash must be exactly 16 bytes"):
            NtlmHash(value=b"a" * 17)

    def test_empty_hash_raises_error(self):
        """Test empty hash raises validation error."""
        with pytest.raises(ValueError, match="NTLM hash value cannot be empty"):
            NtlmHash(value=b"")

    def test_from_hexstring_valid(self):
        """Test creating NTLM hash from valid hex string."""
        hex_string = "aabbccddeeff00112233445566778899"
        ntlm_hash = NtlmHash.from_hexstring(hex_string)
        expected_bytes = bytes.fromhex(hex_string)
        assert ntlm_hash.value == expected_bytes

    def test_from_hexstring_invalid(self):
        """Test creating NTLM hash from invalid hex string."""
        with pytest.raises(ValueError, match="Invalid hex string"):
            NtlmHash.from_hexstring("invalid_hex")

        with pytest.raises(ValueError, match="Invalid hex string"):
            NtlmHash.from_hexstring("aabbcc")  # Wrong length


class TestSha1Hash:
    """Test Sha1Hash model."""

    def test_valid_sha1_hash(self):
        """Test creating valid SHA1 hash."""
        hash_bytes = b"a" * 20  # 20 bytes
        sha1_hash = Sha1Hash(value=hash_bytes)
        assert sha1_hash.value == hash_bytes

    def test_invalid_length_raises_error(self):
        """Test invalid length raises validation error."""
        with pytest.raises(ValueError, match="SHA1 hash must be exactly 20 bytes"):
            Sha1Hash(value=b"a" * 19)

        with pytest.raises(ValueError, match="SHA1 hash must be exactly 20 bytes"):
            Sha1Hash(value=b"a" * 21)

    def test_empty_hash_raises_error(self):
        """Test empty hash raises validation error."""
        with pytest.raises(ValueError, match="SHA1 hash value cannot be empty"):
            Sha1Hash(value=b"")

    def test_from_hex_valid(self):
        """Test creating SHA1 hash from valid hex string."""
        hex_string = "aabbccddeeff00112233445566778899aabbccdd"
        sha1_hash = Sha1Hash.from_hex(hex_string)
        expected_bytes = bytes.fromhex(hex_string)
        assert sha1_hash.value == expected_bytes

    def test_from_hex_invalid(self):
        """Test creating SHA1 hash from invalid hex string."""
        with pytest.raises(ValueError, match="Invalid hex string"):
            Sha1Hash.from_hex("invalid_hex")

        with pytest.raises(ValueError, match="Invalid hex string"):
            Sha1Hash.from_hex("aabbcc")  # Wrong length


class TestPbkdf2Hash:
    """Test Pbkdf2Hash model."""

    def test_valid_pbkdf2_hash(self):
        """Test creating valid PBKDF2 hash."""
        hash_bytes = b"a" * 16  # 16 bytes
        pbkdf2_hash = Pbkdf2Hash(value=hash_bytes)
        assert pbkdf2_hash.value == hash_bytes

    def test_invalid_length_raises_error(self):
        """Test invalid length raises validation error."""
        with pytest.raises(ValueError, match="PBKDF2 hash must be exactly 16 bytes"):
            Pbkdf2Hash(value=b"a" * 15)

        with pytest.raises(ValueError, match="PBKDF2 hash must be exactly 16 bytes"):
            Pbkdf2Hash(value=b"a" * 17)

    def test_empty_hash_raises_error(self):
        """Test empty hash raises validation error."""
        with pytest.raises(ValueError, match="PBKDF2 hash value cannot be empty"):
            Pbkdf2Hash(value=b"")

    def test_from_hex_valid(self):
        """Test creating PBKDF2 hash from valid hex string."""
        hex_string = "aabbccddeeff00112233445566778899"
        pbkdf2_hash = Pbkdf2Hash.from_hex(hex_string)
        expected_bytes = bytes.fromhex(hex_string)
        assert pbkdf2_hash.value == expected_bytes

    def test_from_hex_invalid(self):
        """Test creating PBKDF2 hash from invalid hex string."""
        with pytest.raises(ValueError, match="Invalid hex string"):
            Pbkdf2Hash.from_hex("invalid_hex")

        with pytest.raises(ValueError, match="Invalid hex string"):
            Pbkdf2Hash.from_hex("aabbcc")  # Wrong length


class TestCredKeyHashType:
    def test_enum_values(self):
        assert CredKeyHashType.MD4.value == "md4"
        assert CredKeyHashType.NTLM.value == "md4"
        assert CredKeyHashType.SHA1.value == "sha1"
        assert CredKeyHashType.PBKDF2.value == "pbkdf2"
        assert CredKeyHashType.SECURE_CRED_KEY.value == "pbkdf2"

    def test_ntlm_md4_alias(self):
        assert CredKeyHashType.NTLM == CredKeyHashType.MD4


class TestCredKey:
    def test_init_with_ntlm_hash(self):
        """Test initialization with NTLM hash."""
        key_bytes = b"a" * 16
        ntlm_hash = NtlmHash(value=key_bytes)
        cred_key = CredKey(key=ntlm_hash)

        assert isinstance(cred_key.key, NtlmHash)
        assert cred_key.key.value == key_bytes
        assert cred_key.owf == CredKeyHashType.NTLM

    def test_init_with_pbkdf2_hash(self):
        """Test initialization with PBKDF2 hash."""
        key_bytes = b"a" * 16
        pbkdf2_hash = Pbkdf2Hash(value=key_bytes)
        cred_key = CredKey(key=pbkdf2_hash)

        assert isinstance(cred_key.key, Pbkdf2Hash)
        assert cred_key.key.value == key_bytes
        assert cred_key.owf == CredKeyHashType.PBKDF2

    def test_init_with_sha1_hash(self):
        """Test initialization with SHA1 hash."""
        key_bytes = b"a" * 20
        sha1_hash = Sha1Hash(value=key_bytes)
        cred_key = CredKey(key=sha1_hash)

        assert isinstance(cred_key.key, Sha1Hash)
        assert cred_key.key.value == key_bytes
        assert cred_key.owf == CredKeyHashType.SHA1

    def test_init_with_direct_parameters(self):
        """Test initialization with direct parameters."""
        ntlm_hash = NtlmHash(value=b"a" * 16)
        cred_key = CredKey(key=ntlm_hash)

        assert cred_key.key == ntlm_hash
        assert cred_key.owf == CredKeyHashType.NTLM

    def test_from_password_ntlm(self):
        """Test creating CredKey from password with NTLM hash."""
        password = "Qwerty12345"

        cred_key = CredKey.from_password(password, CredKeyHashType.NTLM)

        assert isinstance(cred_key.key, NtlmHash)
        assert cred_key.owf == CredKeyHashType.NTLM

        expected_hash = "abd9ffb762c86b26ef4ce5c81b0dd37f"
        assert cred_key.key.value.hex() == expected_hash

    def test_from_password_sha1(self):
        """Test creating CredKey from password with SHA1 hash."""
        password = "Qwerty12345"
        cred_key = CredKey.from_password(password, CredKeyHashType.SHA1)

        assert isinstance(cred_key.key, Sha1Hash)
        assert cred_key.owf == CredKeyHashType.SHA1

        expected_hash = "15056cbc481efd37bba0e97e9c28493a40cf8745"
        assert cred_key.key.value.hex() == expected_hash

    def test_from_password_pbkdf2(self):
        """Test creating CredKey from password with PBKDF2 hash."""
        password = "Qwerty12345"

        with pytest.raises(ValueError, match="user_sid parameter is required"):
            CredKey.from_password(password, CredKeyHashType.PBKDF2)

        cred_key = CredKey.from_password(password, CredKeyHashType.PBKDF2, user_sid)

        assert isinstance(cred_key.key, Pbkdf2Hash)
        assert cred_key.owf == CredKeyHashType.PBKDF2

        expected_hash = "775ec403415b49002386ea8e477346cd"
        assert cred_key.key.value.hex() == expected_hash

    def test_from_password_md4_explicit(self):
        """Test creating CredKey from password with explicit MD4 hash type."""
        password = "Qwerty12345"

        cred_key = CredKey.from_password(password, CredKeyHashType.MD4)

        assert isinstance(cred_key.key, NtlmHash)
        assert cred_key.owf == CredKeyHashType.MD4

        expected_hash = "abd9ffb762c86b26ef4ce5c81b0dd37f"
        assert cred_key.key.value.hex() == expected_hash

    def test_from_password_secure_cred_key(self):
        """Test creating CredKey from password with SECURE_CRED_KEY alias."""
        password = "Qwerty12345"

        cred_key = CredKey.from_password(password, CredKeyHashType.SECURE_CRED_KEY, user_sid)

        assert isinstance(cred_key.key, Pbkdf2Hash)
        assert cred_key.owf == CredKeyHashType.PBKDF2

        expected_hash = "775ec403415b49002386ea8e477346cd"
        assert cred_key.key.value.hex() == expected_hash

    def test_from_password_unsupported_type(self):
        """Test creating CredKey from password with unsupported type."""
        password = "TestPassword123"

        with pytest.raises(ValueError, match="Unsupported hash type"):
            # Using string instead of enum to test error handling
            CredKey.from_password(password, "unsupported")  # type: ignore

    def test_from_ntlm_ntlm(self):
        """Test creating CredKey from NTLM hash (explicit NTLM type)."""
        ntlm_bytes = b"a" * 16
        cred_key = CredKey.from_ntlm(ntlm_bytes, CredKeyHashType.NTLM)

        assert isinstance(cred_key.key, NtlmHash)
        assert cred_key.key.value == ntlm_bytes
        assert cred_key.owf == CredKeyHashType.NTLM

    def test_from_ntlm_md4(self):
        """Test creating CredKey from NTLM hash with explicit MD4 type."""
        ntlm_bytes = b"a" * 16
        cred_key = CredKey.from_ntlm(ntlm_bytes, CredKeyHashType.MD4)

        assert isinstance(cred_key.key, NtlmHash)
        assert cred_key.key.value == ntlm_bytes
        assert cred_key.owf == CredKeyHashType.MD4

    def test_from_ntlm_pbkdf2(self):
        """Test creating CredKey from NTLM hash with PBKDF2 derivation."""
        ntlm_hash = "abd9ffb762c86b26ef4ce5c81b0dd37f"  # Qwerty12345
        ntlm_bytes = bytes.fromhex(ntlm_hash)

        with pytest.raises(ValueError, match="user_sid parameter is required"):
            CredKey.from_ntlm(ntlm_bytes, CredKeyHashType.PBKDF2)

        user_sid = "S-1-5-21-3821320868-1508310791-3575676346-1103"
        cred_key = CredKey.from_ntlm(ntlm_bytes, CredKeyHashType.PBKDF2, user_sid=user_sid)

        assert isinstance(cred_key.key, Pbkdf2Hash)
        assert cred_key.owf == CredKeyHashType.PBKDF2

        expected_hash = "775ec403415b49002386ea8e477346cd"
        assert cred_key.key.value.hex() == expected_hash

    def test_from_ntlm_invalid_derivation(self):
        """Test creating CredKey from NTLM hash with invalid derivation."""
        ntlm_bytes = b"a" * 16

        with pytest.raises(ValueError, match="Cannot derive"):
            CredKey.from_ntlm(ntlm_bytes, CredKeyHashType.SHA1)

    def test_from_sha1(self):
        """Test creating CredKey from SHA1 hash."""
        sha1_bytes = b"a" * 20
        cred_key = CredKey.from_sha1(sha1_bytes)

        assert isinstance(cred_key.key, Sha1Hash)
        assert cred_key.key.value == sha1_bytes
        assert cred_key.owf == CredKeyHashType.SHA1

    def test_from_pbkdf2(self):
        """Test creating CredKey from PBKDF2 hash."""
        pbkdf2_bytes = bytes.fromhex(credkey_pbkdf2_hash)
        cred_key = CredKey.from_pbkdf2(pbkdf2_bytes)

        assert isinstance(cred_key.key, Pbkdf2Hash)
        assert cred_key.key.value == pbkdf2_bytes
        assert cred_key.owf == CredKeyHashType.PBKDF2


class TestMasterKeyEncryptionKey:
    """Test MasterKeyEncryptionKey model."""

    def test_from_cred_key_ntlm(self):
        """Test creating MasterKeyEncryptionKey from CredKey with NTLM."""
        global ntlm_bytes, user_sid

        ntlm_hash = NtlmHash(value=ntlm_bytes)
        cred_key = CredKey(key=ntlm_hash)

        mk_key = MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)

        assert isinstance(mk_key.key, Sha1Hash)
        assert len(mk_key.key.value) == 20  # SHA1 digest length

        expected_sha1 = "44857a618c3d58f37823f016c2ff10a0d7b93ee7"
        assert mk_key.key.value.hex() == expected_sha1

    def test_from_cred_key_sha1(self):
        """Test creating MasterKeyEncryptionKey from CredKey with SHA1."""
        global user_sid

        sha1_hash = Sha1Hash(value=bytes.fromhex(credkey_sha1_hash))
        cred_key = CredKey(key=sha1_hash)

        mk_key = MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)

        assert isinstance(mk_key.key, Sha1Hash)
        assert len(mk_key.key.value) == 20  # SHA1 digest length
        assert mk_key.key.value.hex() == "0a66b6fa245e40118aab0c9d71774bf540045f9c"

    def test_from_cred_key_pbkdf2(self):
        """Test creating MasterKeyEncryptionKey from CredKey with PBKDF2."""
        global user_sid, credkey_pbkdf2_hash

        pbkdf2_hash = Pbkdf2Hash(value=bytes.fromhex(credkey_pbkdf2_hash))
        cred_key = CredKey(key=pbkdf2_hash)

        mk_key = MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)

        assert isinstance(mk_key.key, Sha1Hash)
        assert len(mk_key.key.value) == 20  # SHA1 digest length
        assert mk_key.key.value.hex() == "d3205d40d3df002fba1936ce075c0b2805fab06d"

    def test_from_dpapi_system_cred(self):
        """Test creating MasterKeyEncryptionKey from DPAPI_SYSTEM credential."""
        dpapi_system_key = b"a" * 20  # 20 bytes for SHA1

        mk_key = MasterKeyEncryptionKey.from_dpapi_system_cred(dpapi_system_key)

        assert isinstance(mk_key.key, Sha1Hash)
        assert mk_key.key.value == dpapi_system_key

    def test_derive_mk_key_with_different_digests(self):
        """Test _derive_mk_key with different digest algorithms."""
        pwdhash = b"a" * 16
        user_sid = "S-1-5-21-1234567890-1234567890-1234567890-1001"

        # Test with sha256
        sha256_key = MasterKeyEncryptionKey._derive_mk_key(pwdhash, user_sid, digest="sha256")
        assert len(sha256_key) == 32  # SHA256 digest length

        # Test with md4
        md4_key = MasterKeyEncryptionKey._derive_mk_key(pwdhash, user_sid, digest="md4")
        assert len(md4_key) == 16  # MD4 digest length

        # Test with sha1 (default)
        sha1_key = MasterKeyEncryptionKey._derive_mk_key(pwdhash, user_sid, digest="sha1")
        assert len(sha1_key) == 20  # SHA1 digest length

    def test_derive_mk_key_with_unsupported_digest(self):
        """Test _derive_mk_key with unsupported digest algorithm."""
        pwdhash = b"a" * 16
        user_sid = "S-1-5-21-1234567890-1234567890-1234567890-1001"

        with pytest.raises(ValueError, match="Unsupported digest algorithm"):
            MasterKeyEncryptionKey._derive_mk_key(pwdhash, user_sid, digest="unsupported")

    def test_from_cred_key_type_mismatch_ntlm(self):
        """Test type mismatch validation for NTLM/MD4 - wrong hash type."""
        # Create a CredKey with SHA1 hash but mock owf to return NTLM
        sha1_hash = Sha1Hash(value=b"a" * 20)
        cred_key = CredKey(key=sha1_hash)

        # Mock the owf property to return NTLM while key is actually SHA1
        with patch.object(type(cred_key), "owf", new_callable=PropertyMock) as mock_owf:
            mock_owf.return_value = CredKeyHashType.NTLM
            with pytest.raises(ValueError, match="Expected NtlmHash for MD4/NTLM key type"):
                MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)

    def test_from_cred_key_type_mismatch_sha1(self):
        """Test type mismatch validation for SHA1 - wrong hash type."""
        # Create a CredKey with NTLM hash but mock owf to return SHA1
        ntlm_hash = NtlmHash(value=ntlm_bytes)
        cred_key = CredKey(key=ntlm_hash)

        # Mock the owf property to return SHA1 while key is actually NTLM
        with patch.object(type(cred_key), "owf", new_callable=PropertyMock) as mock_owf:
            mock_owf.return_value = CredKeyHashType.SHA1
            with pytest.raises(ValueError, match="Expected Sha1Hash for SHA1 key type"):
                MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)

    def test_from_cred_key_type_mismatch_pbkdf2(self):
        """Test type mismatch validation for PBKDF2 - wrong hash type."""
        # Create a CredKey with NTLM hash but mock owf to return PBKDF2
        ntlm_hash = NtlmHash(value=ntlm_bytes)
        cred_key = CredKey(key=ntlm_hash)

        # Mock the owf property to return PBKDF2 while key is actually NTLM
        with patch.object(type(cred_key), "owf", new_callable=PropertyMock) as mock_owf:
            mock_owf.return_value = CredKeyHashType.PBKDF2
            with pytest.raises(ValueError, match="Expected Pbkdf2Hash for PBKDF2 key type"):
                MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)


class TestHelperFunctions:
    """Test crypto helper functions."""

    def test_derive_secure_cred_key(self):
        """Test _derive_secure_cred_key function directly."""
        ntlm_hash = bytes.fromhex("abd9ffb762c86b26ef4ce5c81b0dd37f")  # Qwerty12345
        user_sid_bytes = "S-1-5-21-3821320868-1508310791-3575676346-1103".encode("utf-16le")

        derived_key = _derive_secure_cred_key(ntlm_hash, user_sid_bytes)

        assert len(derived_key) == 16  # PBKDF2 returns 16 bytes
        assert derived_key == bytes.fromhex("775ec403415b49002386ea8e477346cd")


class TestDomainBackupKey:
    """Test DomainBackupKey dataclass."""

    def test_create_domain_backup_key(self, get_file_path):
        """Test creating DomainBackupKey."""
        # Load valid backup key data from fixtures
        backupkey_file = get_file_path("backupkey.json")
        with open(backupkey_file) as f:
            backupkey_data = json.load(f)

        guid = UUID(backupkey_data["backup_key_guid"])
        key_data = base64.b64decode(backupkey_data["key"])
        domain_controller = backupkey_data["dc"]

        backup_key = DomainBackupKey(guid=guid, key_data=key_data, domain_controller=domain_controller)

        assert backup_key.guid == guid
        assert backup_key.key_data == key_data
        assert backup_key.domain_controller == domain_controller

    def test_create_domain_backup_key_no_dc(self, get_file_path):
        """Test creating DomainBackupKey without domain controller."""
        # Load valid backup key data from fixtures
        backupkey_file = get_file_path("backupkey.json")
        with open(backupkey_file) as f:
            backupkey_data = json.load(f)

        guid = UUID(backupkey_data["backup_key_guid"])
        key_data = base64.b64decode(backupkey_data["key"])

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
        decrypted_masterkey = masterkey_file.decrypt(backup_key)

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
        decrypted_masterkey = masterkey_file.decrypt(backup_key)

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
        await manager.upsert_domain_backup_key(backup_key)

        await manager.upsert_masterkey(
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

        # Create a backup key with fake data (bypassing validation using model_construct)
        backup_key = DomainBackupKey.model_construct(guid=uuid4(), key_data=b"fake_key_data")

        # Load the local masterkey file (no domain backup key)
        masterkey_file = MasterKeyFile.parse("tests/fixtures/masterkey_local.bin")

        # Should raise MasterKeyDecryptionError since no domain backup key in file
        with pytest.raises(ValueError, match="contains no domain backup key"):
            masterkey_file.decrypt(backup_key)

    def test_domain_backup_key_validation(self):
        """Test that DomainBackupKey validates key_data format."""
        from uuid import uuid4

        guid = uuid4()

        # Test with invalid key data (too short)
        with pytest.raises(ValueError, match="key_data too short"):
            DomainBackupKey(guid=guid, key_data=b"too_short")

        # Test with empty key data
        with pytest.raises(ValueError, match="key_data too short"):
            DomainBackupKey(guid=guid, key_data=b"")

        # Test with non-bytes key data should be caught by Pydantic
        with pytest.raises(ValueError):
            DomainBackupKey(guid=guid, key_data="not_bytes")  # type: ignore

    def test_decrypt_masterkey_file_unexpected_key_length(self, get_file_path):
        """Test decrypting masterkey with unexpected decrypted key length."""
        from unittest.mock import MagicMock, patch

        # Load valid backup key and masterkey file
        backupkey_file = get_file_path("backupkey.json")
        with open(backupkey_file) as f:
            backupkey_data = json.load(f)

        backup_key = DomainBackupKey(
            guid=UUID(backupkey_data["backup_key_guid"]),
            key_data=base64.b64decode(backupkey_data["key"]),
            domain_controller=backupkey_data["dc"],
        )

        masterkey_file = MasterKeyFile.parse(get_file_path("masterkey_domain.bin"))

        # Mock the cipher.decrypt to return unexpected length
        with patch("nemesis_dpapi.core.PKCS1_v1_5") as mock_pkcs:
            mock_cipher = MagicMock()
            # Return decrypted key with unexpected length (not 104 or 128)
            mock_cipher.decrypt.return_value = b"X" * 100  # 100 bytes (unexpected)
            mock_pkcs.new.return_value = mock_cipher

            with pytest.raises(Exception, match="Unexpected decrypted key length"):
                masterkey_file.decrypt(backup_key)

    def test_parse_backup_key(self):
        backup_key_b64 = "HvG1sAAAAAABAAAAAAAAAAAAAACUBAAABwIAAACkAABSU0EyAAgAAAEAAQBBif0kcBLSPpOCv+azdnH4mDEDV5UDHl6AVhDmI8AcZPBmYm0/ftO5xXFmsqrQvt9iZsWQP7nG1nzMjGdRq1F9jFKjIqVTjdzgPwEBXxQln6MCqaHPjx6K8/J6He06Y/mf4MueNDv+kWMEsnyayM3Se3RqYia8dR0PAmzJgntKIqbDG8S5c3WbfF3QYhGldkBPgAPuESB0EPg3TcAvXVP88/6oe9BIV8TzYH6CRFd7PaBdq+0YTRejKWALjPrRoNpEW0Uyosgeu4txQNjf57UbOKU4fJ6VoJYRDqvvw1+O4Lui4R6g+gwEByr2W09rcHg2LCEJDUvQSNvRf/FBoq3Hl3Ub7vWs5no65gerQAA0odxPbPKG1MKaexd9bsYynJMwm6TFn/0ram1AxBZrk2Vd9etnefYr4+6ztGaoY9cf5tUG6nK3TUQdLGs6ohmb4JGsRIO6VpLvYylCD+5hpwaDPiqM2il8nHaMLR+QDrRtu2OHzgzgAX0uKP+jq5CNnNbnwvbkyKf75TzcwXzC28d70wl78ud9GkGYmbUY2b/nvkquGsZbnBEV6hIqpZOyTr6SfCmbx9neH5dPhzOm3boXSRiZI/XXCjCk6xvoyyfLiDeatbnEOgGC/+vd5qYVLjR154CCwbQoHfORsTN5q6XlyfBpaYp+qYzl8x/n09Ev7lGLM8FLgLqvOIwwpmzlKCFxFU8JOxOubp4x6/Fgy8nx7m5wtD2uam4WKiKlX26IxCQNAzfThXsjuTi2kaE6vvIk+TM9OkD/ZdzIEIZ62/GVdy1Ns3GMQbk1fBq2+idtQiAweg4zubsoGr2kk0DbbSKrOf9nmxMK/jNP+SKlPrKxExtYlkZbJc//P0IuQ90C4uTZELAADBWWtZrDYozmA3sMnIUQRv6CZMpRU70FKkKqnGtjXtQgX3R6OhIqj5tyCkxu4sFKg4nLzzT4GrMLIqHjtSQ7TuCV4C0yUlJ8PGMKMXBTD0k2IoYbuzKkPfoc6TFaAKf6F0qgH7ZfJgHOD9bWhTP8U8UG3Bo3cHIZXWbg25VE0YQpFxxoNRIHTfLbz5W7opcY5I9ljfQ61+5qkZNcMGl7AGJBU5EJzBQnoJv1DiN0HuoFZHDFoKiq/KV1YkTLDf3yTqCNPWhuwOXOYwDjzM9QyC6tH76jv7fegIu5v2RurhXqLp4IxlnVEYL3AWGexfArKxhmuymUsggEz/y9pOGZdKrmbjixg1vLR3nPAUYnYCmMXc6jAa8HijoTQH0h9d7swEbvPMCH+P1eOUdvW9QxY6GZL3329jUQoIr2zYrUDh0X92q9ZsGkGaNW1P6iHYrZBIwtebNegjcSMboLgeeYxHCPjycfl3shLEu3vV7Wi6VPa6k77ezYYxeelqc6PMjcy2nhHslEoISf3KNH3lpk0/fc0xrTDpZcPpYXr5sI0KZh5IyAwriiqvY9ksSz6tNNS41h0xnWAjtSBITDJnbHJNK3SvCH5gM3/zVrI0RvlLrQaiYMMGd5W2WPSoq0YMKp39ByP+mKMcAn2ic="
        backup_key_bytes = base64.b64decode(backup_key_b64, validate=True)

        from Cryptodome.Cipher import PKCS1_v1_5
        from impacket.dpapi import PRIVATE_KEY_BLOB, PVK_FILE_HDR, privatekeyblob_to_pkcs1

        # Extract the private key from the backup key data
        key = PRIVATE_KEY_BLOB(backup_key_bytes[len(PVK_FILE_HDR()) :])
        private = privatekeyblob_to_pkcs1(key)
        cipher = PKCS1_v1_5.new(private)


class TestDpapiSystemSecret:
    """Tests for DpapiSystemSecret class."""

    def test_from_bytes_valid_40_bytes(self):
        """Test creating DpapiSystemSecret from valid 40-byte data."""
        # Create test data: 20 bytes user key + 20 bytes machine key
        user_key_data = b"user_key_12345678901"  # 20 bytes
        machine_key_data = b"mach_key_12345678901"  # 20 bytes
        dpapi_system_data = machine_key_data + user_key_data  # 40 bytes total, machine key first

        secret = DpapiSystemCredential.from_bytes(dpapi_system_data)

        assert secret.user_key == user_key_data
        assert secret.machine_key == machine_key_data

    def test_from_bytes_with_hex_string(self):
        """Test creating DpapiSystemSecret from hex string."""
        # Use the actual test data hex strings
        hex_string = dpapi_system_machine_user_key_hex  # 40 bytes as hex (80 chars)

        secret = DpapiSystemCredential.from_bytes(hex_string)

        assert secret.user_key == bytes.fromhex(dpapi_system_user_key_hex)
        assert secret.machine_key == bytes.fromhex(dpapi_system_machine_key_hex)

    def test_from_bytes_with_invalid_hex_string(self):
        """Test from_bytes with invalid hex string raises error."""
        invalid_hex = "not_valid_hex_string"

        with pytest.raises(ValueError, match="Invalid hex string"):
            DpapiSystemCredential.from_bytes(invalid_hex)

    def test_from_bytes_with_hex_string_wrong_length(self):
        """Test from_bytes with hex string of wrong length."""
        # 60 hex chars = 30 bytes (not 40)
        wrong_length_hex = "a" * 60

        with pytest.raises(ValueError, match="DPAPI_SYSTEM must be exactly 40 bytes, got 30"):
            DpapiSystemCredential.from_bytes(wrong_length_hex)

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

    def test_serialization_to_json(self):
        """Test serialization of DpapiSystemCredential to JSON."""
        user_key = bytes.fromhex(dpapi_system_user_key_hex)
        machine_key = bytes.fromhex(dpapi_system_machine_key_hex)

        credential = DpapiSystemCredential(user_key=user_key, machine_key=machine_key)

        # Serialize to dict
        data = credential.model_dump()

        assert data["user_key"] == dpapi_system_user_key_hex
        assert data["machine_key"] == dpapi_system_machine_key_hex

    def test_deserialization_from_json(self):
        """Test deserialization of DpapiSystemCredential from JSON with hex strings."""
        # Create data dict with hex strings (as would be received from JSON)
        data = {"user_key": dpapi_system_user_key_hex, "machine_key": dpapi_system_machine_key_hex}

        # Deserialize from dict
        credential = DpapiSystemCredential(**data)

        # Verify bytes are correctly deserialized
        assert credential.user_key == bytes.fromhex(dpapi_system_user_key_hex)
        assert credential.machine_key == bytes.fromhex(dpapi_system_machine_key_hex)

    def test_round_trip_serialization(self):
        """Test round-trip serialization/deserialization maintains data integrity."""
        user_key = bytes.fromhex(dpapi_system_user_key_hex)
        machine_key = bytes.fromhex(dpapi_system_machine_key_hex)

        original = DpapiSystemCredential(user_key=user_key, machine_key=machine_key)

        # Serialize to dict
        data = original.model_dump()

        # Deserialize back
        restored = DpapiSystemCredential(**data)

        # Verify they match
        assert restored.user_key == original.user_key
        assert restored.machine_key == original.machine_key
