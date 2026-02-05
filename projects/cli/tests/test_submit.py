"""Tests for cli.submit module - UploadTracker, filters, metadata, file streaming."""

import json
import tempfile
from pathlib import Path
from queue import Queue

import pytest
from cli.submit import (
    UploadTracker,
    calculate_metadata_path,
    create_metadata,
    create_session_with_retries,
    parse_filters,
    stream_files,
    validate_filters,
)

# --- UploadTracker ---


class TestUploadTracker:
    def test_initial_state(self):
        tracker = UploadTracker()
        assert tracker.successful == 0
        assert tracker.failed == 0
        assert tracker.bytes_uploaded == 0
        assert tracker.total_files == 0

    def test_add_success(self):
        tracker = UploadTracker()
        tracker.add_success(Path("/tmp/file.txt"), 1024)
        assert tracker.successful == 1
        assert tracker.bytes_uploaded == 1024
        assert tracker.total_files == 1

    def test_add_failure(self):
        tracker = UploadTracker()
        tracker.add_failure(Path("/tmp/file.txt"), "Connection error")
        assert tracker.failed == 1
        assert tracker.total_files == 1

    def test_total_files_combines_success_and_failure(self):
        tracker = UploadTracker()
        tracker.add_success(Path("/a"), 100)
        tracker.add_success(Path("/b"), 200)
        tracker.add_failure(Path("/c"), "err")
        assert tracker.total_files == 3

    def test_format_bytes_bytes(self):
        tracker = UploadTracker()
        tracker.add_success(Path("/a"), 512)
        result = tracker.format_bytes()
        assert "512.00 B" == result

    def test_format_bytes_kilobytes(self):
        tracker = UploadTracker()
        tracker.add_success(Path("/a"), 2048)
        result = tracker.format_bytes()
        assert "2.00 KB" == result

    def test_format_bytes_megabytes(self):
        tracker = UploadTracker()
        tracker.add_success(Path("/a"), 5 * 1024 * 1024)
        result = tracker.format_bytes()
        assert "5.00 MB" == result

    def test_format_bytes_gigabytes(self):
        tracker = UploadTracker()
        tracker.add_success(Path("/a"), 3 * 1024**3)
        result = tracker.format_bytes()
        assert "3.00 GB" == result

    def test_format_duration(self):
        tracker = UploadTracker()
        result = tracker.format_duration(3661.5)
        assert result == "01:01:01.50 (3661.50s)"

    def test_format_duration_short(self):
        tracker = UploadTracker()
        result = tracker.format_duration(5.25)
        assert result == "00:00:05.25 (5.25s)"

    def test_get_failures_returns_copy(self):
        tracker = UploadTracker()
        tracker.add_failure(Path("/a"), "err1")
        failures = tracker.get_failures()
        assert len(failures) == 1
        # Modifying the returned list shouldn't affect the original
        failures.clear()
        assert len(tracker.get_failures()) == 1

    def test_get_successes_returns_copy(self):
        tracker = UploadTracker()
        tracker.add_success(Path("/a"), 100)
        successes = tracker.get_successes()
        assert len(successes) == 1
        successes.clear()
        assert len(tracker.get_successes()) == 1

    def test_thread_safety(self):
        """Verify concurrent adds don't corrupt state."""
        import threading

        tracker = UploadTracker()
        threads = []
        for i in range(100):
            if i % 2 == 0:
                t = threading.Thread(target=tracker.add_success, args=(Path(f"/f{i}"), 10))
            else:
                t = threading.Thread(target=tracker.add_failure, args=(Path(f"/f{i}"), "err"))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        assert tracker.total_files == 100
        assert tracker.successful == 50
        assert tracker.failed == 50


# --- parse_filters ---


class TestParseFilters:
    def test_no_filters_returns_none(self):
        result = parse_filters(None, (), (), "glob")
        assert result is None

    def test_include_patterns(self):
        result = parse_filters(None, ("*.exe", "*.dll"), (), "glob")
        assert result == {"pattern_type": "glob", "include": ["*.exe", "*.dll"]}

    def test_exclude_patterns(self):
        result = parse_filters(None, (), ("*/temp/*",), "regex")
        assert result == {"pattern_type": "regex", "exclude": ["*/temp/*"]}

    def test_both_include_and_exclude(self):
        result = parse_filters(None, ("*.exe",), ("*/temp/*",), "glob")
        assert result == {"pattern_type": "glob", "include": ["*.exe"], "exclude": ["*/temp/*"]}

    def test_filters_file(self):
        filters_data = {"include": ["*.exe"], "pattern_type": "glob"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(filters_data, f)
            f.flush()
            result = parse_filters(f.name, (), (), "glob")
        assert result == filters_data

    def test_filters_file_adds_default_pattern_type(self):
        filters_data = {"include": ["*.exe"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(filters_data, f)
            f.flush()
            result = parse_filters(f.name, (), (), "regex")
        assert result["pattern_type"] == "regex"

    def test_filters_file_with_inline_patterns_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"include": ["*.exe"]}, f)
            f.flush()
            with pytest.raises(ValueError, match="Cannot specify both"):
                parse_filters(f.name, ("*.dll",), (), "glob")

    def test_invalid_json_file_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json{{{")
            f.flush()
            with pytest.raises(ValueError, match="Invalid JSON"):
                parse_filters(f.name, (), (), "glob")


# --- validate_filters ---


class TestValidateFilters:
    def test_valid_include_filters(self):
        validate_filters({"include": ["*.exe"], "pattern_type": "glob"})

    def test_valid_exclude_filters(self):
        validate_filters({"exclude": ["*/temp/*"], "pattern_type": "regex"})

    def test_valid_both_filters(self):
        validate_filters({"include": ["*.exe"], "exclude": ["*/temp/*"], "pattern_type": "glob"})

    def test_unknown_fields_raises(self):
        with pytest.raises(ValueError, match="Unknown filter fields"):
            validate_filters({"include": ["*.exe"], "unknown_field": True})

    def test_invalid_pattern_type_raises(self):
        with pytest.raises(ValueError, match="pattern_type must be"):
            validate_filters({"include": ["*.exe"], "pattern_type": "invalid"})

    def test_no_include_or_exclude_raises(self):
        with pytest.raises(ValueError, match="At least one"):
            validate_filters({"pattern_type": "glob"})

    def test_include_not_list_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            validate_filters({"include": "*.exe"})

    def test_include_non_string_elements_raises(self):
        with pytest.raises(ValueError, match="must be strings"):
            validate_filters({"include": [123]})

    def test_non_dict_raises(self):
        with pytest.raises(ValueError, match="must be a dictionary"):
            validate_filters("not a dict")

    def test_default_pattern_type(self):
        """If pattern_type is not specified, default to glob (valid)."""
        validate_filters({"include": ["*.exe"]})


# --- create_metadata ---


class TestCreateMetadata:
    def test_basic_metadata(self):
        result = create_metadata("/path/to/file.txt", "project-1", "agent-1")
        assert result["agent_id"] == "agent-1"
        assert result["project"] == "project-1"
        assert result["path"] == "/path/to/file.txt"
        assert "source" not in result
        assert "file_filters" not in result

    def test_with_source(self):
        result = create_metadata("/file.txt", "p", "a", source="host://10.0.0.1")
        assert result["source"] == "host://10.0.0.1"

    def test_with_file_filters(self):
        filters = {"include": ["*.exe"], "pattern_type": "glob"}
        result = create_metadata("/file.txt", "p", "a", file_filters=filters)
        assert result["file_filters"] == filters

    def test_with_invalid_filters_raises(self):
        """create_metadata calls validate_filters internally."""
        with pytest.raises(ValueError):
            create_metadata("/file.txt", "p", "a", file_filters={"bad_field": True})


# --- calculate_metadata_path ---


class TestCalculateMetadataPath:
    def test_no_folder_returns_path_as_is(self):
        result = calculate_metadata_path(Path("/tmp/file.txt"), None, None)
        assert result == "/tmp/file.txt"

    def test_no_base_paths_returns_path_as_is(self):
        result = calculate_metadata_path(Path("/tmp/file.txt"), [], "C:\\Users")
        assert result == "/tmp/file.txt"

    def test_folder_transformation(self, tmp_path):
        # Create a test file structure
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        test_file = data_dir / "subdir" / "file.txt"
        test_file.parent.mkdir(parents=True)
        test_file.touch()

        result = calculate_metadata_path(test_file, [data_dir], "C:\\Users\\Admin\\Documents")
        assert result == "C:\\Users\\Admin\\Documents/subdir/file.txt"

    def test_folder_with_file_base(self, tmp_path):
        test_file = tmp_path / "file.txt"
        test_file.touch()

        result = calculate_metadata_path(test_file, [test_file], "C:\\Users\\Admin")
        assert result == "C:\\Users\\Admin/file.txt"

    def test_file_not_under_any_base(self, tmp_path):
        test_file = tmp_path / "file.txt"
        test_file.touch()
        other_base = tmp_path / "other"
        other_base.mkdir()

        result = calculate_metadata_path(test_file, [other_base], "C:\\Users")
        assert result == str(test_file)

    def test_empty_folder_string(self, tmp_path):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        test_file = data_dir / "file.txt"
        test_file.touch()

        result = calculate_metadata_path(test_file, [data_dir], "")
        assert result == "file.txt"


# --- stream_files ---


class TestStreamFiles:
    def test_single_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        queue = Queue()
        count = stream_files([f], recursive=False, file_queue=queue)
        assert count == 1
        assert queue.get() == f

    def test_directory_non_recursive(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f1.write_text("a")
        sub = tmp_path / "sub"
        sub.mkdir()
        f2 = sub / "b.txt"
        f2.write_text("b")

        queue = Queue()
        count = stream_files([tmp_path], recursive=False, file_queue=queue)
        assert count == 1  # only a.txt, not sub/b.txt

    def test_directory_recursive(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f1.write_text("a")
        sub = tmp_path / "sub"
        sub.mkdir()
        f2 = sub / "b.txt"
        f2.write_text("b")

        queue = Queue()
        count = stream_files([tmp_path], recursive=True, file_queue=queue)
        assert count == 2

    def test_max_files_limit(self, tmp_path):
        for i in range(10):
            (tmp_path / f"file_{i}.txt").write_text(str(i))

        queue = Queue()
        count = stream_files([tmp_path], recursive=False, file_queue=queue, max_files=3)
        assert count == 3

    def test_nonexistent_path(self):
        queue = Queue()
        count = stream_files([Path("/nonexistent/path")], recursive=False, file_queue=queue)
        assert count == 0

    def test_multiple_paths(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f1.write_text("a")
        f2 = tmp_path / "b.txt"
        f2.write_text("b")

        queue = Queue()
        count = stream_files([f1, f2], recursive=False, file_queue=queue)
        assert count == 2


# --- create_session_with_retries ---


class TestCreateSessionWithRetries:
    def test_returns_session(self):
        session = create_session_with_retries()
        assert session is not None
        session.close()

    def test_custom_max_workers(self):
        session = create_session_with_retries(max_workers=50)
        assert session is not None
        session.close()

    def test_session_has_adapters(self):
        session = create_session_with_retries()
        assert "https://" in session.adapters
        assert "http://" in session.adapters
        session.close()
