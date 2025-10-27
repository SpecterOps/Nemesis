"""Tests for the file linking rules engine."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from common.models import FileEnriched, FileHashes
from file_linking.rules_engine import FileLinkingEngine, Trigger


@pytest.fixture
def mock_asyncpg_pool():
    """Create a mock asyncpg.Pool for testing."""
    pool = MagicMock()
    pool.acquire = MagicMock()
    pool.acquire.return_value.__aenter__ = AsyncMock()
    pool.acquire.return_value.__aexit__ = AsyncMock()
    return pool


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
    def engine(self, tmp_path, mock_asyncpg_pool):
        """Create a FileLinkingEngine instance with a temporary rules directory."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Using a mock asyncpg pool since we're only testing _matches_trigger
        return FileLinkingEngine(connection_pool=mock_asyncpg_pool, rules_dir=str(rules_dir))

    def test_matches_trigger_chromium_cookies(self, engine):
        """Test matching Chromium cookies with various trigger conditions."""
        cookies_path = "/C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"
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
    def engine(self, tmp_path, mock_asyncpg_pool):
        """Create a FileLinkingEngine with the actual chromium cookies rule."""
        # Use the real rules directory to load the cookies.yaml rule
        import os

        rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "file_linking", "rules")
        return FileLinkingEngine(connection_pool=mock_asyncpg_pool, rules_dir=rules_dir)

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


class TestChromiumLocalStateLinking:
    """Tests for Chromium Local State linking to Login Data and Cookies files."""

    @pytest.fixture
    def engine(self, tmp_path, mock_asyncpg_pool):
        """Create a FileLinkingEngine with the actual chromium local_state rule."""
        import os

        rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "file_linking", "rules")
        return FileLinkingEngine(connection_pool=mock_asyncpg_pool, rules_dir=rules_dir)

    def test_chromium_local_state_links_to_login_data_and_cookies_windows(self, engine):
        """Test that Chromium Local State file creates links to Login Data and Cookies on Windows paths."""
        local_state_path = "C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Local State"
        expected_login_data_path = "C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Login Data"
        expected_cookies_path = "C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"

        file_local_state = create_file_enriched(
            object_id="test-local-state-001",
            path=local_state_path,
            mime_type="application/json",
            magic_type="JSON data",
        )

        # Find the chromium_local_state rule
        rule = next((r for r in engine.rules if r.name == "chromium_local_state"), None)
        assert rule is not None, "chromium_local_state rule should be loaded"
        assert rule.enabled is True, "chromium_local_state rule should be enabled"

        # Verify the rule triggers
        trigger_matched = False
        for trigger in rule.triggers:
            if engine._matches_trigger(file_local_state, trigger):
                trigger_matched = True
                break
        assert trigger_matched is True, "Local State file should match the rule trigger"

        # Verify the linked files configuration
        assert len(rule.linked_files) == 2, "Should have exactly two linked files"

        # Check login_data linked file
        login_data_file = next((lf for lf in rule.linked_files if lf.name == "login_data"), None)
        assert login_data_file is not None, "Should have login_data linked file"
        assert login_data_file.priority == "high", "login_data priority should be high"
        assert "login credentials" in login_data_file.collection_reason.lower(), "Should mention login credentials"

        # Check cookies linked file
        cookies_file = next((lf for lf in rule.linked_files if lf.name == "cookies"), None)
        assert cookies_file is not None, "Should have cookies linked file"
        assert cookies_file.priority == "high", "cookies priority should be high"
        assert "cookie" in cookies_file.collection_reason.lower(), "Should mention cookies"

        # Verify path template expansion for login_data
        assert len(login_data_file.path_templates) == 1, "login_data should have exactly one path template"
        login_template = login_data_file.path_templates[0]
        expanded_login_path = engine._expand_path_template(login_template, local_state_path)
        assert expanded_login_path == expected_login_data_path, f"Expected {expected_login_data_path}, got {expanded_login_path}"

        # Verify path template expansion for cookies
        assert len(cookies_file.path_templates) == 1, "cookies should have exactly one path template"
        cookies_template = cookies_file.path_templates[0]
        expanded_cookies_path = engine._expand_path_template(cookies_template, local_state_path)
        assert expanded_cookies_path == expected_cookies_path, f"Expected {expected_cookies_path}, got {expanded_cookies_path}"

    def test_chromium_local_state_links_opera_browser(self, engine):
        """Test that Opera browser Local State file creates correct links."""
        local_state_path = "C:/Users/Bob/AppData/Roaming/Opera Software/Opera Stable/Local State"
        expected_login_data_path = "C:/Users/Bob/AppData/Roaming/Opera Software/Opera Stable/Default/Login Data"
        expected_cookies_path = "C:/Users/Bob/AppData/Roaming/Opera Software/Opera Stable/Default/Network/Cookies"

        file_local_state = create_file_enriched(
            object_id="test-local-state-opera-001",
            path=local_state_path,
            mime_type="application/json",
            magic_type="JSON data",
        )

        # Find the chromium_local_state rule
        rule = next((r for r in engine.rules if r.name == "chromium_local_state"), None)
        assert rule is not None, "chromium_local_state rule should be loaded"

        # Verify the rule triggers for Opera paths
        trigger_matched = False
        for trigger in rule.triggers:
            if engine._matches_trigger(file_local_state, trigger):
                trigger_matched = True
                break
        assert trigger_matched is True, "Opera Local State file should match the rule trigger"

        # Verify path template expansion
        login_data_file = next((lf for lf in rule.linked_files if lf.name == "login_data"), None)
        cookies_file = next((lf for lf in rule.linked_files if lf.name == "cookies"), None)

        expanded_login_path = engine._expand_path_template(login_data_file.path_templates[0], local_state_path)
        expanded_cookies_path = engine._expand_path_template(cookies_file.path_templates[0], local_state_path)

        assert expanded_login_path == expected_login_data_path, f"Expected {expected_login_data_path}, got {expanded_login_path}"
        assert expanded_cookies_path == expected_cookies_path, f"Expected {expected_cookies_path}, got {expanded_cookies_path}"

    def test_chromium_local_state_links_posix_paths(self, engine):
        """Test that Local State file works with POSIX-style paths (e.g., from Linux collection)."""
        local_state_path = "/C/Users/Alice/AppData/Local/Google/Chrome/User Data/Local State"
        expected_login_data_path = "/C/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Login Data"
        expected_cookies_path = "/C/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"

        file_local_state = create_file_enriched(
            object_id="test-local-state-posix-001",
            path=local_state_path,
            mime_type="application/json",
            magic_type="JSON data",
        )

        # Find the chromium_local_state rule
        rule = next((r for r in engine.rules if r.name == "chromium_local_state"), None)
        assert rule is not None, "chromium_local_state rule should be loaded"

        # Verify the rule triggers
        trigger_matched = False
        for trigger in rule.triggers:
            if engine._matches_trigger(file_local_state, trigger):
                trigger_matched = True
                break
        assert trigger_matched is True, "POSIX-style Local State file should match the rule trigger"

        # Verify path template expansion
        login_data_file = next((lf for lf in rule.linked_files if lf.name == "login_data"), None)
        cookies_file = next((lf for lf in rule.linked_files if lf.name == "cookies"), None)

        expanded_login_path = engine._expand_path_template(login_data_file.path_templates[0], local_state_path)
        expanded_cookies_path = engine._expand_path_template(cookies_file.path_templates[0], local_state_path)

        assert expanded_login_path == expected_login_data_path, f"Expected {expected_login_data_path}, got {expanded_login_path}"
        assert expanded_cookies_path == expected_cookies_path, f"Expected {expected_cookies_path}, got {expanded_cookies_path}"

    def test_chromium_local_state_wrong_mime_type_no_match(self, engine):
        """Test that a file with the right path but wrong MIME type doesn't trigger the rule."""
        local_state_path = "C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Local State"

        file_wrong_mime = create_file_enriched(
            object_id="test-local-state-004",
            path=local_state_path,
            mime_type="text/plain",  # Wrong MIME type
            magic_type="ASCII text",
        )

        # Find the chromium_local_state rule
        rule = next((r for r in engine.rules if r.name == "chromium_local_state"), None)
        assert rule is not None, "chromium_local_state rule should be loaded"

        # Verify the rule does NOT trigger
        trigger_matched = False
        for trigger in rule.triggers:
            if engine._matches_trigger(file_wrong_mime, trigger):
                trigger_matched = True
                break
        assert trigger_matched is False, "File with wrong MIME type should not match"

    def test_chromium_local_state_wrong_path_no_match(self, engine):
        """Test that a JSON file with the wrong path doesn't trigger the rule."""
        wrong_path = "C:/Users/Alice/AppData/Local/Google/Chrome/User Data/Default/Preferences"

        file_wrong_path = create_file_enriched(
            object_id="test-preferences-001",
            path=wrong_path,
            mime_type="application/json",
            magic_type="JSON data",
        )

        # Find the chromium_local_state rule
        rule = next((r for r in engine.rules if r.name == "chromium_local_state"), None)
        assert rule is not None, "chromium_local_state rule should be loaded"

        # Verify the rule does NOT trigger
        trigger_matched = False
        for trigger in rule.triggers:
            if engine._matches_trigger(file_wrong_path, trigger):
                trigger_matched = True
                break
        assert trigger_matched is False, "Preferences file should not match local_state rule"


@pytest.mark.asyncio
class TestPlaceholderResolutionIntegration:
    """Integration tests for placeholder resolution in file linking."""

    @pytest.fixture
    def engine(self, tmp_path, mock_asyncpg_pool):
        """Create a FileLinkingEngine with test database."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        # Using a mock pool since we're testing logic, not actual DB
        engine = FileLinkingEngine(connection_pool=mock_asyncpg_pool, rules_dir=str(rules_dir))

        # Mock the database service methods (now async)
        engine.db_service.add_file_listing = AsyncMock(return_value=True)
        engine.db_service.add_file_linking = AsyncMock(return_value=True)

        return engine

    async def test_forward_resolution_placeholder_first_real_file_later(self, engine):
        """Test forward resolution: placeholder exists in DB, real file arrives."""
        from unittest.mock import AsyncMock

        # Setup: Placeholder entry already exists
        placeholder_path = "/C:/Users/<WINDOWS_USERNAME>/AppData/Roaming/file.txt"
        engine.db_service.get_placeholder_entries = AsyncMock(
            return_value=[{"table_name": "file_listings", "path": placeholder_path}]
        )
        engine.db_service.update_file_listing_path = AsyncMock(return_value=True)

        # Real file arrives
        real_file = create_file_enriched(
            object_id="test-file-001",
            path="/C:/Users/john.doe/AppData/Roaming/file.txt",
            mime_type="application/octet-stream",
            magic_type="data",
        )
        real_file.source = "test-agent"

        # Process the file (which triggers forward resolution)
        await engine.apply_linking_rules(real_file)

        # Verify forward resolution was called and placeholder was updated
        # Called twice: once for file_listings, once for file_linkings
        assert engine.db_service.get_placeholder_entries.call_count == 2
        engine.db_service.update_file_listing_path.assert_called_once()
        call_args = engine.db_service.update_file_listing_path.call_args
        assert call_args[0][1] == placeholder_path  # old path
        assert call_args[0][2] == "/C:/Users/john.doe/AppData/Roaming/file.txt"  # new path

    async def test_backward_resolution_real_file_first_placeholder_later(self, engine):
        """Test backward resolution: real file exists, placeholder path created."""
        from pathlib import Path
        from unittest.mock import AsyncMock

        # Setup: Real file already collected
        real_path = "/C:/Users/john.doe/AppData/Roaming/Microsoft/Protect/S-1-5-21-123-456-789-1000/abc123"
        engine.db_service.get_collected_files = AsyncMock(return_value=[real_path])
        engine.db_service.get_placeholder_entries = AsyncMock(return_value=[])

        # Create a rule that generates a placeholder path

        rule_content = """
name: "test_placeholder_rule"
description: "Test rule that creates placeholder paths"
category: "test"
enabled: true

triggers:
  - file_patterns:
      - "**/Local State"
    mime_patterns:
      - "application/json"

linked_files:
  - name: "masterkey"
    description: "User masterkey"
    path_templates:
      - "{parent_dir}/../../../Roaming/Microsoft/Protect/<WINDOWS_SECURITY_IDENTIFIER>/abc123"
    priority: "high"
    collection_reason: "Test placeholder"
"""
        rule_file = Path(engine.rules_dir) / "test.yaml"
        with open(rule_file, "w") as f:
            f.write(rule_content)

        # Reload rules
        engine._load_rules()

        # Trigger file that creates placeholder path
        trigger_file = create_file_enriched(
            object_id="test-trigger-001",
            path="/C:/Users/john.doe/AppData/Local/Google/Chrome/User Data/Local State",
            mime_type="application/json",
            magic_type="JSON data",
        )
        trigger_file.source = "test-agent"

        # Process the trigger file
        await engine.apply_linking_rules(trigger_file)

        # Verify backward resolution was attempted
        engine.db_service.get_collected_files.assert_called()

    async def test_chromium_masterkey_resolution_full_path(self, engine):
        """Test resolution of Chromium masterkey with full paths."""
        from unittest.mock import AsyncMock

        placeholder_path = (
            "/C:/Users/<WINDOWS_USERNAME>/AppData/Roaming/Microsoft/Protect/"
            "<WINDOWS_SECURITY_IDENTIFIER>/abc-123-def-456"
        )
        real_path = (
            "/C:/Users/john.doe/AppData/Roaming/Microsoft/Protect/"
            "S-1-5-21-1234567890-1234567890-1234567890-1000/abc-123-def-456"
        )

        engine.db_service.get_placeholder_entries = AsyncMock(
            return_value=[{"table_name": "file_listings", "path": placeholder_path}]
        )
        engine.db_service.update_file_listing_path = AsyncMock(return_value=True)

        # Real masterkey file arrives
        masterkey_file = create_file_enriched(
            object_id="test-masterkey-001",
            path=real_path,
            mime_type="application/octet-stream",
            magic_type="data",
        )
        masterkey_file.source = "test-agent"

        await engine.apply_linking_rules(masterkey_file)

        # Verify resolution occurred
        engine.db_service.update_file_listing_path.assert_called_once()
        call_args = engine.db_service.update_file_listing_path.call_args
        assert "john.doe" in call_args[0][2]
        assert "S-1-5-21-" in call_args[0][2]

    async def test_username_placeholder_resolution(self, engine):
        """Test USERNAME placeholder resolution."""
        from unittest.mock import AsyncMock

        placeholder_path = "/C:/Users/<WINDOWS_USERNAME>/Documents/file.txt"
        real_path = "/C:/Users/alice.smith/Documents/file.txt"

        engine.db_service.get_placeholder_entries = AsyncMock(
            return_value=[{"table_name": "file_listings", "path": placeholder_path}]
        )
        engine.db_service.update_file_listing_path = AsyncMock(return_value=True)

        file_enriched = create_file_enriched(
            object_id="test-001", path=real_path, mime_type="text/plain", magic_type="ASCII text"
        )
        file_enriched.source = "test-agent"

        await engine.apply_linking_rules(file_enriched)

        engine.db_service.update_file_listing_path.assert_called_once()
        call_args = engine.db_service.update_file_listing_path.call_args
        assert call_args[0][2] == real_path

    async def test_sid_placeholder_resolution(self, engine):
        """Test SID placeholder resolution."""
        from unittest.mock import AsyncMock

        placeholder_path = "/C:/Windows/System32/Config/systemprofile/AppData/Local/<WINDOWS_SECURITY_IDENTIFIER>/file.dat"
        real_path = "/C:/Windows/System32/Config/systemprofile/AppData/Local/S-1-5-18/file.dat"

        engine.db_service.get_placeholder_entries = AsyncMock(
            return_value=[{"table_name": "file_listings", "path": placeholder_path}]
        )
        engine.db_service.update_file_listing_path = AsyncMock(return_value=True)

        file_enriched = create_file_enriched(
            object_id="test-001", path=real_path, mime_type="application/octet-stream", magic_type="data"
        )
        file_enriched.source = "test-agent"

        await engine.apply_linking_rules(file_enriched)

        engine.db_service.update_file_listing_path.assert_called_once()
        call_args = engine.db_service.update_file_listing_path.call_args
        assert "S-1-5-18" in call_args[0][2]

    async def test_both_placeholders_same_path(self, engine):
        """Test multiple placeholders in the same path."""
        from unittest.mock import AsyncMock

        placeholder_path = (
            "/C:/Users/<WINDOWS_USERNAME>/AppData/Roaming/Microsoft/Protect/"
            "<WINDOWS_SECURITY_IDENTIFIER>/masterkey"
        )
        real_path = (
            "/C:/Users/bob.jones/AppData/Roaming/Microsoft/Protect/"
            "S-1-5-21-9876543210-9876543210-9876543210-5000/masterkey"
        )

        engine.db_service.get_placeholder_entries = AsyncMock(
            return_value=[{"table_name": "file_listings", "path": placeholder_path}]
        )
        engine.db_service.update_file_listing_path = AsyncMock(return_value=True)

        file_enriched = create_file_enriched(
            object_id="test-001", path=real_path, mime_type="application/octet-stream", magic_type="data"
        )
        file_enriched.source = "test-agent"

        await engine.apply_linking_rules(file_enriched)

        engine.db_service.update_file_listing_path.assert_called_once()
        call_args = engine.db_service.update_file_listing_path.call_args
        resolved_path = call_args[0][2]
        assert "bob.jones" in resolved_path
        assert "S-1-5-21-" in resolved_path

    async def test_no_resolution_when_no_match(self, engine):
        """Test that placeholder stays when no matching file exists."""
        from unittest.mock import AsyncMock

        # Placeholder for different path
        placeholder_path = "/C:/Users/<WINDOWS_USERNAME>/AppData/different.txt"

        engine.db_service.get_placeholder_entries = AsyncMock(
            return_value=[{"table_name": "file_listings", "path": placeholder_path}]
        )
        engine.db_service.update_file_listing_path = AsyncMock(return_value=True)

        # Real file with non-matching path
        file_enriched = create_file_enriched(
            object_id="test-001",
            path="/C:/Users/john.doe/Documents/other.txt",
            mime_type="text/plain",
            magic_type="ASCII text",
        )
        file_enriched.source = "test-agent"

        await engine.apply_linking_rules(file_enriched)

        # No resolution should occur
        engine.db_service.update_file_listing_path.assert_not_called()

    async def test_case_insensitive_windows_paths(self, engine):
        """Test that resolution works with different case variations."""
        from unittest.mock import AsyncMock

        placeholder_path = "/C:/Users/<WINDOWS_USERNAME>/AppData/file.txt"
        real_path_different_case = "/c:/users/john.doe/appdata/file.txt"

        engine.db_service.get_placeholder_entries = AsyncMock(
            return_value=[{"table_name": "file_listings", "path": placeholder_path}]
        )
        engine.db_service.update_file_listing_path = AsyncMock(return_value=True)

        file_enriched = create_file_enriched(
            object_id="test-001", path=real_path_different_case, mime_type="text/plain", magic_type="ASCII text"
        )
        file_enriched.source = "test-agent"

        await engine.apply_linking_rules(file_enriched)

        # Should resolve despite case differences
        engine.db_service.update_file_listing_path.assert_called_once()

    async def test_source_isolation(self, engine):
        """Test that placeholders from different sources don't cross-resolve."""
        from unittest.mock import AsyncMock

        # Placeholder from source-1
        placeholder_path = "/C:/Users/<WINDOWS_USERNAME>/AppData/file.txt"
        engine.db_service.get_placeholder_entries = AsyncMock(
            return_value=[]  # No placeholders for source-2
        )

        # Real file from source-2 (different source)
        file_enriched = create_file_enriched(
            object_id="test-001",
            path="/C:/Users/john.doe/AppData/file.txt",
            mime_type="text/plain",
            magic_type="ASCII text",
        )
        file_enriched.source = "source-2"

        await engine.apply_linking_rules(file_enriched)

        # Verify query was called with correct source
        engine.db_service.get_placeholder_entries.assert_called_with("source-2")
