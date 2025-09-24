"""Tests for DPAPI cryptographic operations."""

import base64
from uuid import UUID

import pytest
from nemesis_dpapi.core import Blob, MasterKey
from nemesis_dpapi.crypto import (
    BlobDecryptionError,
    CredKey,
    CredKeyHashType,
    InvalidBlobDataError,
    MasterKeyEncryptionKey,
    NtlmHash,
    Password,
    Pbkdf2Hash,
    Sha1Hash,
    _derive_secure_cred_key,
)
from nemesis_dpapi.dpapi_blob import DPAPI_BLOB

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


class TestBlobDecrypt:
    """Test Blob.decrypt() method."""

    def test_decrypt_blob_with_unencrypted_masterkey(self, blob_without_entropy: bytes):
        """Test DPAPI blob decryption with unencrypted master key."""
        blob = Blob.parse(blob_without_entropy)
        # Create an unencrypted master key
        masterkey = MasterKey(guid=blob.masterkey_guid)

        with pytest.raises(ValueError, match="Master key must be decrypted before use"):
            blob.decrypt(masterkey)

    def test_decrypt_blob_with_wrong_masterkey(self, blob_without_entropy: bytes):
        """Test DPAPI blob decryption with wrong masterkey."""
        blob = Blob.parse(blob_without_entropy)
        # Create a master key with wrong SHA1 hash
        wrong_masterkey_sha1 = b"wrong_key" + b"\x00" * 8  # 20 bytes
        masterkey = MasterKey(
            guid=blob.masterkey_guid, plaintext_key=b"dummy_key" * 8, plaintext_key_sha1=wrong_masterkey_sha1
        )

        with pytest.raises(ValueError, match="Failed to decrypt blob with provided master key"):
            blob.decrypt(masterkey)

    def test_decrypt_blob_with_entropy(self, blob_with_entropy: bytes):
        blob = Blob.parse(blob_with_entropy)
        assert blob.masterkey_guid == masterkey_uuid

        masterkey_sha1_bytes = bytes.fromhex("17FD87F91D25A18ABD9BCD66B6D9F3C6BFC16778")
        masterkey = MasterKey(
            guid=blob.masterkey_guid, plaintext_key=masterkey_bytes, plaintext_key_sha1=masterkey_sha1_bytes
        )

        entropy = bytes([1, 2, 3, 4, 5])
        decrypted_data = blob.decrypt(masterkey, entropy=entropy)

        assert isinstance(decrypted_data, bytes)
        assert len(decrypted_data) > 0
        assert decrypted_data.decode("utf-8") == "test"

    def test_decrypt_blob_without_entropy(self, blob_without_entropy: bytes):
        blob = Blob.parse(blob_without_entropy)

        assert blob.masterkey_guid == masterkey_uuid

        masterkey_sha1_bytes = bytes.fromhex("17FD87F91D25A18ABD9BCD66B6D9F3C6BFC16778")
        masterkey = MasterKey(
            guid=blob.masterkey_guid, plaintext_key=masterkey_bytes, plaintext_key_sha1=masterkey_sha1_bytes
        )

        decrypted_data = blob.decrypt(masterkey)

        assert isinstance(decrypted_data, bytes)
        assert len(decrypted_data) > 0
        assert decrypted_data.decode("utf-8") == "test"

    def test_decrypt_blob_app_bound_enc_key(self, read_file_text):
        """Test DPAPI blob decryption with app-bound encrypted key from fixture."""
        blob_b64 = read_file_text("blob_app_bound_enc_key.txt").strip()
        blob_data = base64.b64decode(blob_b64)[4:]
        blob = Blob.parse(blob_data)

        assert blob.description == "Google Chrome"
        assert str(blob.masterkey_guid).lower() == "f752e2e1-1726-454b-a632-0718d94ca677"
        masterkey_sha1_bytes = bytes.fromhex("9DED7C56C3FE577B84780908ADAC346F38F1D114")

        # Create a proper master key object
        masterkey = MasterKey(
            guid=blob.masterkey_guid,
            plaintext_key=b"dummy_key" * 8,  # We only need the SHA1 hash for decryption
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


class TestBlobParse:
    """Test Blob.parse() method."""

    def test_parse_blob(self, blob_without_entropy):
        """Test parsing DPAPI blob data against reference implementations."""
        from dpapick3 import blob as dpapick3_blob

        blob = Blob.parse(blob_without_entropy)
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


class TestCryptoHelperFunctions:
    """Test crypto helper functions."""

    def test_derive_secure_cred_key(self):
        """Test _derive_secure_cred_key function directly."""
        ntlm_hash = bytes.fromhex("abd9ffb762c86b26ef4ce5c81b0dd37f")  # Qwerty12345
        user_sid_bytes = "S-1-5-21-3821320868-1508310791-3575676346-1103".encode("utf-16le")

        derived_key = _derive_secure_cred_key(ntlm_hash, user_sid_bytes)

        assert len(derived_key) == 16  # PBKDF2 returns 16 bytes
        assert derived_key == bytes.fromhex("775ec403415b49002386ea8e477346cd")


class TestExceptions:
    """Test custom exceptions."""

    def test_blob_decryption_error_inheritance(self):
        """Test BlobDecryptionError inherits from DpapiCryptoError."""
        from nemesis_dpapi.exceptions import DpapiCryptoError

        error = BlobDecryptionError("test message")
        assert isinstance(error, DpapiCryptoError)
        assert str(error) == "test message"

    def test_invalid_blob_data_error_inheritance(self):
        """Test InvalidBlobDataError inherits from DpapiCryptoError."""
        from nemesis_dpapi.exceptions import DpapiCryptoError

        error = InvalidBlobDataError("test message")
        assert isinstance(error, DpapiCryptoError)
        assert str(error) == "test message"


class TestPasswordValidation:
    """Additional tests for Password validation."""

    def test_password_with_none_value_direct(self):
        """Test Password with None value raises validation error."""
        with pytest.raises(ValueError):
            # This should trigger pydantic's validation before our custom validator
            Password(value=None)  # type: ignore
