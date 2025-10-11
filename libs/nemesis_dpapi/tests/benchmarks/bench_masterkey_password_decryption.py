"""Benchmarks for DPAPI masterkey decryption using password credentials."""

import pytest
from nemesis_dpapi.core import MasterKey, MasterKeyFile, MasterKeyType
from nemesis_dpapi.keys import CredKey, CredKeyHashType, MasterKeyEncryptionKey


class TestMasterkeyPasswordDecryptionBenchmarks:
    """Benchmark tests for masterkey decryption using password credentials."""

    def test_single_password_masterkey_decryption(self, benchmark, get_file_path):
        """Benchmark decrypting a single masterkey using password."""
        # Load masterkey file that can be decrypted with password
        masterkey_file_path = get_file_path("masterkey_domain.bin")
        masterkey_file = MasterKeyFile.from_file(masterkey_file_path)

        # Create MasterKey object from the file
        masterkey = MasterKey(
            guid=masterkey_file.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
            encrypted_key_usercred=masterkey_file.master_key,
        )

        # Test password and SID from the test fixtures
        password = "Qwerty12345"
        user_sid = "S-1-5-21-3821320868-1508310791-3575676346-1103"

        # Create encryption key from password using PBKDF2 (most secure method)
        cred_key = CredKey.from_password(password, CredKeyHashType.PBKDF2, user_sid)
        mk_encryption_key = MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)

        # Verify setup works
        test_result = masterkey.decrypt(mk_encryption_key)
        assert test_result.is_decrypted, "Test decryption failed - benchmark cannot proceed"

        # Run benchmark
        result = benchmark(masterkey.decrypt, mk_encryption_key)

        # Verify result
        assert result.is_decrypted
        assert result.plaintext_key is not None

    def test_password_multiple_hash_types(self, benchmark, get_file_path):
        """Benchmark trying multiple hash types for password-based decryption."""
        # Load masterkey file
        masterkey_file_path = get_file_path("masterkey_domain.bin")
        masterkey_file = MasterKeyFile.from_file(masterkey_file_path)

        # Create MasterKey object from the file
        masterkey = MasterKey(
            guid=masterkey_file.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
            encrypted_key_usercred=masterkey_file.master_key,
        )

        password = "Qwerty12345"
        user_sid = "S-1-5-21-3821320868-1508310791-3575676346-1103"

        def try_multiple_hash_types():
            """Try decrypting with different hash types until successful."""
            hash_types = [CredKeyHashType.PBKDF2, CredKeyHashType.SHA1, CredKeyHashType.NTLM]

            for hash_type in hash_types:
                try:
                    if hash_type == CredKeyHashType.PBKDF2:
                        cred_key = CredKey.from_password(password, hash_type, user_sid)
                    else:
                        cred_key = CredKey.from_password(password, hash_type)

                    mk_encryption_key = MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)
                    result = masterkey.decrypt(mk_encryption_key)

                    if result.is_decrypted:
                        return result
                except Exception:
                    continue

            return None

        # Verify setup works
        test_result = try_multiple_hash_types()
        assert test_result is not None and test_result.is_decrypted, "Test decryption failed - benchmark cannot proceed"

        # Run benchmark
        result = benchmark(try_multiple_hash_types)

        # Verify result
        assert result is not None
        assert result.is_decrypted
        assert result.plaintext_key is not None

    @pytest.mark.parametrize("hash_type", [CredKeyHashType.PBKDF2, CredKeyHashType.SHA1, CredKeyHashType.NTLM])
    def test_password_by_hash_type(self, benchmark, get_file_path, hash_type):
        """Benchmark password decryption for specific hash types."""
        # Load masterkey file
        masterkey_file_path = get_file_path("masterkey_domain.bin")
        masterkey_file = MasterKeyFile.from_file(masterkey_file_path)

        # Create MasterKey object from the file
        masterkey = MasterKey(
            guid=masterkey_file.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
            encrypted_key_usercred=masterkey_file.master_key,
        )

        password = "Qwerty12345"
        user_sid = "S-1-5-21-3821320868-1508310791-3575676346-1103"

        # Create encryption key with specific hash type
        if hash_type == CredKeyHashType.PBKDF2:
            cred_key = CredKey.from_password(password, hash_type, user_sid)
        else:
            cred_key = CredKey.from_password(password, hash_type)

        mk_encryption_key = MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)

        # Add context info
        benchmark.extra_info["hash_type"] = hash_type.value

        # Try to decrypt - some hash types might not work for this specific masterkey
        try:
            test_result = masterkey.decrypt(mk_encryption_key)
            if not test_result.is_decrypted:
                pytest.skip(f"Hash type {hash_type.value} does not decrypt this masterkey")
        except Exception:
            pytest.skip(f"Hash type {hash_type.value} does not decrypt this masterkey")

        # Run benchmark
        result = benchmark(masterkey.decrypt, mk_encryption_key)

        # Verify result
        assert result.is_decrypted
        assert result.plaintext_key is not None

    @pytest.mark.parametrize("iterations", [1, 10, 20])
    def test_batch_password_decryption(self, benchmark, get_file_path, iterations):
        """Benchmark multiple consecutive password-based masterkey decryptions."""
        # Load masterkey file
        masterkey_file_path = get_file_path("masterkey_domain.bin")
        masterkey_file = MasterKeyFile.from_file(masterkey_file_path)

        # Create MasterKey object from the file
        masterkey = MasterKey(
            guid=masterkey_file.masterkey_guid,
            masterkey_type=MasterKeyType.UNKNOWN,
            encrypted_key_usercred=masterkey_file.master_key,
        )

        password = "Qwerty12345"
        user_sid = "S-1-5-21-3821320868-1508310791-3575676346-1103"

        # Create encryption key
        cred_key = CredKey.from_password(password, CredKeyHashType.PBKDF2, user_sid)
        mk_encryption_key = MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)

        def batch_decrypt():
            results = []
            for _ in range(iterations):
                result = masterkey.decrypt(mk_encryption_key)
                results.append(result)
            return results

        # Verify setup works
        test_result = masterkey.decrypt(mk_encryption_key)
        assert test_result.is_decrypted, "Test decryption failed - benchmark cannot proceed"

        # Add context info
        benchmark.extra_info["iterations"] = iterations

        # Benchmark
        results = benchmark(batch_decrypt)

        # Verify all successful
        assert len(results) == iterations
        for result in results:
            assert result.is_decrypted
            assert result.plaintext_key is not None

    def test_password_key_derivation_benchmark(self, benchmark, get_file_path):
        """Benchmark just the password-to-key derivation process."""
        password = "Qwerty12345"
        user_sid = "S-1-5-21-3821320868-1508310791-3575676346-1103"

        def derive_encryption_key():
            """Create encryption key from password."""
            cred_key = CredKey.from_password(password, CredKeyHashType.PBKDF2, user_sid)
            return MasterKeyEncryptionKey.from_cred_key(cred_key, user_sid)

        # Verify setup works
        test_key = derive_encryption_key()
        assert test_key is not None

        # Run benchmark
        result = benchmark(derive_encryption_key)

        # Verify result
        assert result is not None
        assert result.key is not None
