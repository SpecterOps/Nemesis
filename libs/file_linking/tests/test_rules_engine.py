"""Tests for the file linking rules engine."""

from datetime import datetime, timedelta

import pytest
from common.models import FileEnriched, FileHashes
from file_linking.rules_engine import FileLinkingEngine, Trigger


def create_file_enriched(object_id: str, path: str, mime_type: str, magic_type: str) -> FileEnriched:
    """Helper function to create a FileEnriched instance with all required fields."""
    return FileEnriched(
        object_id=object_id,
        agent_id="test-agent-id",
        project="test-project",
        timestamp=datetime.now(),
        expiration=datetime.now() + timedelta(days=30),
        path=path,
        file_name=path.split("/")[-1],
        size=1024,
        hashes=FileHashes(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        magic_type=magic_type,
        mime_type=mime_type,
        is_plaintext=False,
        is_container=False,
    )


class TestMatchesTrigger:
    """Tests for the _matches_trigger method."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create a FileLinkingEngine instance with a temporary rules directory."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Using a dummy postgres connection string since we're only testing _matches_trigger
        return FileLinkingEngine(postgres_connection_string="postgresql://dummy", rules_dir=str(rules_dir))

    def test_matches_trigger_chromium_cookies(self, engine):
        """Test matching Chromium cookies with various trigger conditions."""
        cookies_path = "C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"
        sqlite_mime = "application/vnd.sqlite3; charset=binary"
        sqlite_magic = "SQLite 3.x database"

        # Test 1: File pattern only - should match
        trigger_file_only = Trigger(
            file_patterns=["**/User Data/Default/Network/Cookies"],
            mime_patterns=[],
            magic_patterns=[],
        )
        file_cookies = create_file_enriched(
            object_id="test-cookies",
            path=cookies_path,
            mime_type=sqlite_mime,
            magic_type=sqlite_magic,
        )
        assert engine._matches_trigger(file_cookies, trigger_file_only) is True

        # Test 2: File pattern no match - should not match: History file is not the Cookies file
        file_history = create_file_enriched(
            object_id="test-history",
            path="C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History",
            mime_type=sqlite_mime,
            magic_type=sqlite_magic,
        )
        assert engine._matches_trigger(file_history, trigger_file_only) is False

        # Test 3: File pattern + MIME type - should match
        trigger_with_mime = Trigger(
            file_patterns=["**/User Data/Default/Network/Cookies"],
            mime_patterns=[sqlite_mime],
            magic_patterns=[],
        )
        assert engine._matches_trigger(file_cookies, trigger_with_mime) is True

        # Test 4: File pattern matches but MIME type doesn't - should not match
        file_wrong_mime = create_file_enriched(
            object_id="test-wrong-mime",
            path=cookies_path,
            mime_type="text/plain",
            magic_type="ASCII text",
        )
        assert engine._matches_trigger(file_wrong_mime, trigger_with_mime) is False

        # Test 5: File pattern + magic pattern - should match
        trigger_with_magic = Trigger(
            file_patterns=["**/User Data/Default/Network/Cookies"],
            mime_patterns=[],
            magic_patterns=["SQLite"],
        )
        assert engine._matches_trigger(file_cookies, trigger_with_magic) is True

        # Test 6: File pattern matches but magic pattern doesn't - should not match
        assert engine._matches_trigger(file_wrong_mime, trigger_with_magic) is False

        # Test 7: All conditions (file + MIME + magic) - should match
        trigger_all = Trigger(
            file_patterns=["**/User Data/Default/Network/Cookies"],
            mime_patterns=[sqlite_mime],
            magic_patterns=["SQLite"],
        )
        assert engine._matches_trigger(file_cookies, trigger_all) is True

    def test_matches_trigger_multiple_file_patterns(self, engine):
        """Test matching with multiple file patterns."""
        trigger = Trigger(
            file_patterns=[
                "**/User Data/Default/Network/Cookies",
                "**/User Data/Profile */Network/Cookies",
            ],
            mime_patterns=[],
            magic_patterns=[],
        )

        # First pattern should match
        file_enriched_1 = create_file_enriched(
            object_id="test-object-id-1",
            path="C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies",
            mime_type="application/vnd.sqlite3; charset=binary",
            magic_type="SQLite 3.x database",
        )
        assert engine._matches_trigger(file_enriched_1, trigger) is True

        # Second pattern should match
        file_enriched_2 = create_file_enriched(
            object_id="test-object-id-2",
            path="C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Profile 1/Network/Cookies",
            mime_type="application/vnd.sqlite3; charset=binary",
            magic_type="SQLite 3.x database",
        )
        assert engine._matches_trigger(file_enriched_2, trigger) is True

    def test_matches_trigger_multiple_mime_patterns(self, engine):
        """Test matching with multiple MIME patterns."""
        trigger = Trigger(
            file_patterns=["**/*.db"],
            mime_patterns=[
                "application/vnd.sqlite3; charset=binary",
                "application/x-sqlite3",
            ],
            magic_patterns=[],
        )

        # First MIME type should match
        file_enriched_1 = create_file_enriched(
            object_id="test-object-id-1",
            path="/home/user/data/app.db",
            mime_type="application/vnd.sqlite3; charset=binary",
            magic_type="SQLite 3.x database",
        )
        assert engine._matches_trigger(file_enriched_1, trigger) is True

        # Second MIME type should match
        file_enriched_2 = create_file_enriched(
            object_id="test-object-id-2",
            path="/home/user/data/app.db",
            mime_type="application/x-sqlite3",
            magic_type="SQLite 3.x database",
        )
        assert engine._matches_trigger(file_enriched_2, trigger) is True

    def test_matches_trigger_empty_trigger_lists(self, engine):
        """Test behavior with empty trigger lists (should match any file)."""
        trigger = Trigger(
            file_patterns=[],
            mime_patterns=[],
            magic_patterns=[],
        )

        file_enriched = create_file_enriched(
            object_id="test-object-id",
            path="/any/path/file.txt",
            mime_type="text/plain",
            magic_type="ASCII text",
        )

        # Empty file_patterns should match any file
        assert engine._matches_trigger(file_enriched, trigger) is True

    def test_matches_trigger_case_sensitive_pattern(self, engine):
        """Test that file pattern matching is case-sensitive (via fnmatch)."""
        trigger = Trigger(
            file_patterns=["**/Cookies"],
            mime_patterns=[],
            magic_patterns=[],
        )

        # Exact case match
        file_enriched_match = create_file_enriched(
            object_id="test-object-id-1",
            path="/path/to/Cookies",
            mime_type="application/octet-stream",
            magic_type="data",
        )
        assert engine._matches_trigger(file_enriched_match, trigger) is True

        # Different case
        file_enriched_no_match = create_file_enriched(
            object_id="test-object-id-2",
            path="/path/to/cookies",
            mime_type="application/octet-stream",
            magic_type="data",
        )
        assert engine._matches_trigger(file_enriched_no_match, trigger) is False

    def test_matches_trigger_posix_path_pattern(self, engine):
        """Test matching with POSIX-style paths."""
        trigger = Trigger(
            file_patterns=["**/config/*.json"],
            mime_patterns=[],
            magic_patterns=[],
        )

        file_enriched = create_file_enriched(
            object_id="test-object-id",
            path="/home/user/.config/app/config/settings.json",
            mime_type="application/json",
            magic_type="JSON data",
        )

        assert engine._matches_trigger(file_enriched, trigger) is True


class TestChromiumCookiesLinking:
    """Tests for Chromium cookies linking to Local State file."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create a FileLinkingEngine with the actual chromium cookies rule."""
        # Use the real rules directory to load the cookies.yaml rule
        import os

        rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "file_linking", "rules")
        return FileLinkingEngine(postgres_connection_string="postgresql://dummy", rules_dir=rules_dir)

    def test_chromium_cookies_links_to_local_state_windows(self, engine):
        """Test that Chromium Cookies file creates a link to Local State on Windows paths."""
        cookies_path = "C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"
        expected_local_state_path = "C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Local State"

        file_cookies = create_file_enriched(
            object_id="test-cookies-001",
            path=cookies_path,
            mime_type="application/vnd.sqlite3; charset=binary",
            magic_type="SQLite 3.x database",
        )

        # Find the chromium_cookies rule
        rule = next((r for r in engine.rules if r.name == "chromium_cookies"), None)
        assert rule is not None, "chromium_cookies rule should be loaded"
        assert rule.enabled is True, "chromium_cookies rule should be enabled"

        # Verify the rule triggers
        trigger_matched = False
        for trigger in rule.triggers:
            if engine._matches_trigger(file_cookies, trigger):
                trigger_matched = True
                break
        assert trigger_matched is True, "Cookies file should match the rule trigger"

        # Verify the linked file configuration
        assert len(rule.linked_files) == 1, "Should have exactly one linked file"
        linked_file = rule.linked_files[0]
        assert linked_file.name == "local_state", "Linked file should be named 'local_state'"
        assert linked_file.priority == "high", "Priority should be high"
        assert "master key" in linked_file.collection_reason.lower(), "Should mention master key in reason"

        # Verify path template expansion
        assert len(linked_file.path_templates) == 1, "Should have exactly one path template"
        template = linked_file.path_templates[0]
        expanded_path = engine._expand_path_template(template, cookies_path)
        assert expanded_path == expected_local_state_path, f"Expected {expected_local_state_path}, got {expanded_path}"

    def test_chromium_cookies_wrong_mime_type_no_match(self, engine):
        """Test that a file with the right path but wrong MIME type doesn't trigger the rule."""
        cookies_path = "C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"

        file_wrong_mime = create_file_enriched(
            object_id="test-cookies-004",
            path=cookies_path,
            mime_type="text/plain",  # Wrong MIME type
            magic_type="ASCII text",
        )

        # Find the chromium_cookies rule
        rule = next((r for r in engine.rules if r.name == "chromium_cookies"), None)
        assert rule is not None, "chromium_cookies rule should be loaded"

        # Verify the rule does NOT trigger
        trigger_matched = False
        for trigger in rule.triggers:
            if engine._matches_trigger(file_wrong_mime, trigger):
                trigger_matched = True
                break
        assert trigger_matched is False, "File with wrong MIME type should not match"

    def test_chromium_cookies_wrong_path_no_match(self, engine):
        """Test that a SQLite file with the wrong path doesn't trigger the rule."""
        history_path = "C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/History"

        file_history = create_file_enriched(
            object_id="test-history-001",
            path=history_path,
            mime_type="application/vnd.sqlite3; charset=binary",
            magic_type="SQLite 3.x database",
        )

        # Find the chromium_cookies rule
        rule = next((r for r in engine.rules if r.name == "chromium_cookies"), None)
        assert rule is not None, "chromium_cookies rule should be loaded"

        # Verify the rule does NOT trigger
        trigger_matched = False
        for trigger in rule.triggers:
            if engine._matches_trigger(file_history, trigger):
                trigger_matched = True
                break
        assert trigger_matched is False, "History file should not match cookies rule"
