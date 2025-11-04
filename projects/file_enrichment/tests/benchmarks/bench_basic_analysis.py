"""Benchmarks for basic file analysis processing.

This benchmark tests the process_basic_analysis function in isolation.
We include a copy of the function here to avoid triggering module-level
Dapr initialization that occurs when importing from the main module.
"""

import pathlib
import posixpath
from datetime import UTC
from uuid import uuid4

import common.helpers as helpers
import magic
import pytest
from common.helpers import get_file_extension, is_container


def process_basic_analysis(temp_file_path: str, file_dict: dict) -> dict:
    """
    Process a file and extract basic metadata including hashes, mime type, etc.

    This is a copy of the function from file_enrichment.activities.basic_analysis
    to allow benchmarking without triggering Dapr initialization.

    Args:
        temp_file_path: Path to the temporary file to analyze
        file_dict: Dictionary containing file metadata (object_id, path, etc.)

    Returns:
        Dictionary with all file enrichment data (file_dict merged with basic_analysis)
    """
    path = file_dict.get("path", "")

    mime_type = magic.from_file(temp_file_path, mime=True)
    if mime_type == "text/plain" or helpers.is_text_file(temp_file_path):
        is_plaintext = True
    else:
        is_plaintext = False

    basic_analysis = {
        "file_name": posixpath.basename(path),
        "extension": get_file_extension(path),
        "size": pathlib.Path(temp_file_path).stat().st_size,
        "hashes": {
            "md5": helpers.calculate_file_hash(temp_file_path, "md5"),
            "sha1": helpers.calculate_file_hash(temp_file_path, "sha1"),
            "sha256": helpers.calculate_file_hash(temp_file_path, "sha256"),
        },
        "magic_type": magic.from_file(temp_file_path),
        "mime_type": mime_type,
        "is_plaintext": is_plaintext,
        "is_container": is_container(mime_type),
    }

    file_enriched = {
        **file_dict,
        **basic_analysis,
    }

    return file_enriched


class TestBasicAnalysisBenchmarks:
    """Benchmark tests for basic file analysis operations."""

    def test_single_text_file_analysis(self, benchmark, get_file_path):
        """Benchmark analyzing a single text file."""
        # Use existing fixture file
        fixture_path = get_file_path("sample.txt")

        # Create file_dict input
        file_dict = {
            "object_id": str(uuid4()),
            "path": "/test/path/sample.txt",
            "agent_id": "test-agent",
            "source": "test",
            "project": "test-project",
        }

        # Verify setup works
        test_result = process_basic_analysis(str(fixture_path), file_dict)
        assert test_result is not None
        assert "file_name" in test_result
        assert test_result["file_name"] == "sample.txt"

        # Run benchmark
        result = benchmark(process_basic_analysis, str(fixture_path), file_dict)

        # Verify result
        assert result is not None
        assert result["is_plaintext"] is True
        assert result["file_name"] == "sample.txt"
        assert result["extension"] == ".txt"
        assert "hashes" in result
        assert "md5" in result["hashes"]
        assert "sha1" in result["hashes"]
        assert "sha256" in result["hashes"]

    def test_single_json_file_analysis(self, benchmark, get_file_path):
        """Benchmark analyzing a single JSON file."""
        fixture_path = get_file_path("sample.json")

        file_dict = {
            "object_id": str(uuid4()),
            "path": "/test/path/sample.json",
            "agent_id": "test-agent",
            "source": "test",
            "project": "test-project",
        }

        # Verify setup works
        test_result = process_basic_analysis(str(fixture_path), file_dict)
        assert test_result is not None

        # Run benchmark
        result = benchmark(process_basic_analysis, str(fixture_path), file_dict)

        # Verify result
        assert result is not None
        assert result["file_name"] == "sample.json"
        assert result["extension"] == ".json"
        assert "hashes" in result

    def test_single_zip_file_analysis(self, benchmark, get_file_path):
        """Benchmark analyzing a single ZIP archive file."""
        fixture_path = get_file_path("sample.zip")

        file_dict = {
            "object_id": str(uuid4()),
            "path": "/test/path/sample.zip",
            "agent_id": "test-agent",
            "source": "test",
            "project": "test-project",
        }

        # Verify setup works
        test_result = process_basic_analysis(str(fixture_path), file_dict)
        assert test_result is not None

        # Run benchmark
        result = benchmark(process_basic_analysis, str(fixture_path), file_dict)

        # Verify result
        assert result is not None
        assert result["file_name"] == "sample.zip"
        assert result["extension"] == ".zip"
        assert result["is_container"] is True
        assert "hashes" in result

    @pytest.mark.parametrize("file_size_kb", [1, 10, 100])
    def test_analysis_by_file_size(self, benchmark, tmp_path, file_size_kb):
        """Benchmark file analysis for different file sizes."""
        # Create a temporary file of specific size
        test_file = tmp_path / f"test_{file_size_kb}kb.bin"
        file_size_bytes = file_size_kb * 1024

        # Write random-ish data
        with open(test_file, "wb") as f:
            # Write chunks to avoid memory issues with large files
            chunk_size = 4096
            remaining = file_size_bytes
            chunk = b"A" * chunk_size
            while remaining > 0:
                write_size = min(chunk_size, remaining)
                f.write(chunk[:write_size])
                remaining -= write_size

        file_dict = {
            "object_id": str(uuid4()),
            "path": f"/test/path/test_{file_size_kb}kb.bin",
            "agent_id": "test-agent",
            "source": "test",
            "project": "test-project",
        }

        # Add context info
        benchmark.extra_info["file_size_kb"] = file_size_kb

        # Verify setup works
        test_result = process_basic_analysis(str(test_file), file_dict)
        assert test_result is not None
        assert test_result["size"] == file_size_bytes

        # Run benchmark
        result = benchmark(process_basic_analysis, str(test_file), file_dict)

        # Verify result
        assert result is not None
        assert result["size"] == file_size_bytes
        assert "hashes" in result

    @pytest.mark.parametrize("iterations", [1, 10, 20])
    def test_batch_file_analysis(self, benchmark, get_file_path, iterations):
        """Benchmark multiple consecutive file analyses."""
        fixture_path = get_file_path("sample.txt")

        def batch_analyze():
            results = []
            for i in range(iterations):
                file_dict = {
                    "object_id": str(uuid4()),
                    "path": f"/test/path/sample_{i}.txt",
                    "agent_id": "test-agent",
                    "source": "test",
                    "project": "test-project",
                }
                result = process_basic_analysis(str(fixture_path), file_dict)
                results.append(result)
            return results

        # Verify setup works
        file_dict = {
            "object_id": str(uuid4()),
            "path": "/test/path/sample.txt",
        }
        test_result = process_basic_analysis(str(fixture_path), file_dict)
        assert test_result is not None

        # Add context info
        benchmark.extra_info["iterations"] = iterations

        # Run benchmark
        results = benchmark(batch_analyze)

        # Verify all successful
        assert len(results) == iterations
        for i, result in enumerate(results):
            assert result is not None
            assert "hashes" in result
            assert result["file_name"] == f"sample_{i}.txt"

    def test_hash_calculation_only(self, benchmark, get_file_path):
        """Benchmark just the hash calculation portion of analysis."""
        import common.helpers as helpers

        fixture_path = get_file_path("sample.txt")

        def calculate_all_hashes():
            """Calculate MD5, SHA1, and SHA256 hashes."""
            return {
                "md5": helpers.calculate_file_hash(str(fixture_path), "md5"),
                "sha1": helpers.calculate_file_hash(str(fixture_path), "sha1"),
                "sha256": helpers.calculate_file_hash(str(fixture_path), "sha256"),
            }

        # Verify setup works
        test_hashes = calculate_all_hashes()
        assert test_hashes is not None
        assert "md5" in test_hashes
        assert "sha1" in test_hashes
        assert "sha256" in test_hashes

        # Run benchmark
        result = benchmark(calculate_all_hashes)

        # Verify result
        assert result is not None
        assert len(result) == 3

    def test_magic_type_detection(self, benchmark, get_file_path):
        """Benchmark magic type detection."""
        import magic

        fixture_path = get_file_path("sample.txt")

        def detect_magic_type():
            """Detect both magic type and mime type."""
            return {
                "magic_type": magic.from_file(str(fixture_path)),
                "mime_type": magic.from_file(str(fixture_path), mime=True),
            }

        # Verify setup works
        test_result = detect_magic_type()
        assert test_result is not None
        assert "magic_type" in test_result
        assert "mime_type" in test_result

        # Run benchmark
        result = benchmark(detect_magic_type)

        # Verify result
        assert result is not None
        assert result["mime_type"] is not None

    @pytest.mark.parametrize(
        "fixture_name,expected_plaintext",
        [
            ("sample.txt", True),
            ("sample.json", True),
            ("sample.zip", False),
        ],
    )
    def test_analysis_by_file_type(self, benchmark, get_file_path, fixture_name, expected_plaintext):
        """Benchmark file analysis for different file types."""
        fixture_path = get_file_path(fixture_name)

        file_dict = {
            "object_id": str(uuid4()),
            "path": f"/test/path/{fixture_name}",
            "agent_id": "test-agent",
            "source": "test",
            "project": "test-project",
        }

        # Add context info
        benchmark.extra_info["file_type"] = fixture_name

        # Verify setup works
        test_result = process_basic_analysis(str(fixture_path), file_dict)
        assert test_result is not None
        assert test_result["is_plaintext"] == expected_plaintext

        # Run benchmark
        result = benchmark(process_basic_analysis, str(fixture_path), file_dict)

        # Verify result
        assert result is not None
        assert result["file_name"] == fixture_name
        assert result["is_plaintext"] == expected_plaintext

    def test_analysis_with_all_optional_fields(self, benchmark, get_file_path):
        """Benchmark analysis with all optional file_dict fields populated."""
        from datetime import datetime

        fixture_path = get_file_path("sample.txt")

        # Create comprehensive file_dict with all optional fields
        file_dict = {
            "object_id": str(uuid4()),
            "path": "/test/path/sample.txt",
            "agent_id": "test-agent",
            "source": "test-source",
            "project": "test-project",
            "timestamp": datetime.now(UTC).isoformat(),
            "expiration": datetime.now(UTC).isoformat(),
            "originating_object_id": str(uuid4()),
            "originating_container_id": str(uuid4()),
            "nesting_level": 0,
            "file_creation_time": datetime.now(UTC).isoformat(),
            "file_access_time": datetime.now(UTC).isoformat(),
            "file_modification_time": datetime.now(UTC).isoformat(),
            "security_info": {"owner": "test-user", "permissions": "0644"},
        }

        # Verify setup works
        test_result = process_basic_analysis(str(fixture_path), file_dict)
        assert test_result is not None

        # Run benchmark
        result = benchmark(process_basic_analysis, str(fixture_path), file_dict)

        # Verify result
        assert result is not None
        assert result["object_id"] == file_dict["object_id"]
        assert result["agent_id"] == file_dict["agent_id"]
        assert "security_info" in result
