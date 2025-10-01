"""Benchmarks for DPAPI masterkey decryption operations."""

import base64
import json
from uuid import UUID

import pytest
from nemesis_dpapi.core import MasterKeyFile
from nemesis_dpapi.keys import DomainBackupKey


class TestMasterkeyDecryptionBenchmarks:
    """Benchmark tests for masterkey decryption operations."""

    def test_single_masterkey_decryption(self, benchmark, get_file_path):
        """Benchmark decrypting a single masterkey using domain backup key."""
        # Load domain backup key
        backup_key_path = get_file_path("backupkey.json")
        with open(backup_key_path) as f:
            backup_key_data = json.load(f)

        backup_key = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )

        # Load masterkey file
        masterkey_file_path = get_file_path("masterkey_domain.bin")
        masterkey_file = MasterKeyFile.parse(masterkey_file_path)

        # Verify setup works
        test_result = masterkey_file.decrypt(backup_key)
        assert test_result.is_decrypted, "Test decryption failed - benchmark cannot proceed"

        # Run benchmark
        result = benchmark(masterkey_file.decrypt, backup_key)

        # Verify result
        assert result.is_decrypted
        assert result.plaintext_key_sha1 is not None
        assert result.plaintext_key_sha1.hex() == "17fd87f91d25a18abd9bcd66b6d9f3c6bfc16778"

    def test_masterkey_decryption_with_warmup(self, benchmark, get_file_path):
        """Benchmark masterkey decryption with warmup runs."""
        # Setup
        backup_key_path = get_file_path("backupkey.json")
        with open(backup_key_path) as f:
            backup_key_data = json.load(f)

        backup_key = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )

        masterkey_file_path = get_file_path("masterkey_domain.bin")
        masterkey_file = MasterKeyFile.parse(masterkey_file_path)

        # Warmup
        for _ in range(5):
            masterkey_file.decrypt(backup_key)

        # Benchmark
        result = benchmark(masterkey_file.decrypt, backup_key)

        # Verify
        assert result.is_decrypted
        assert result.plaintext_key_sha1 is not None
        assert result.plaintext_key_sha1.hex() == "17fd87f91d25a18abd9bcd66b6d9f3c6bfc16778"

    @pytest.mark.parametrize("iterations", [1, 10, 100])
    def test_batch_masterkey_decryption(self, benchmark, get_file_path, iterations):
        """Benchmark multiple consecutive masterkey decryptions."""
        # Setup
        backup_key_path = get_file_path("backupkey.json")
        with open(backup_key_path) as f:
            backup_key_data = json.load(f)

        backup_key = DomainBackupKey(
            guid=UUID(backup_key_data["backup_key_guid"]),
            key_data=base64.b64decode(backup_key_data["key"]),
            domain_controller=backup_key_data["dc"],
        )

        masterkey_file_path = get_file_path("masterkey_domain.bin")
        masterkey_file = MasterKeyFile.parse(masterkey_file_path)

        def batch_decrypt():
            results = []
            for _ in range(iterations):
                result = masterkey_file.decrypt(backup_key)
                results.append(result)
            return results

        # Add context info
        benchmark.extra_info["iterations"] = iterations

        # Benchmark
        results = benchmark(batch_decrypt)

        # Verify all successful
        assert len(results) == iterations
        for result in results:
            assert result.is_decrypted
            assert result.plaintext_key_sha1 is not None
            assert result.plaintext_key_sha1.hex() == "17fd87f91d25a18abd9bcd66b6d9f3c6bfc16778"
