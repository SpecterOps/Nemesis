"""Tests for the placeholder resolver."""

import re
from unittest.mock import AsyncMock, MagicMock

import pytest
from file_linking.placeholder_resolver import (
    PLACEHOLDERS,
    PlaceholderDefinition,
    PlaceholderResolver,
)


class TestPlaceholderDefinition:
    """Tests for PlaceholderDefinition dataclass."""

    def test_placeholder_definition_creation(self):
        """Test creating a PlaceholderDefinition."""
        placeholder = PlaceholderDefinition(name="<TEST>", pattern=r"([a-z]+)", description="Test placeholder")

        assert placeholder.name == "<TEST>"
        assert placeholder.pattern == r"([a-z]+)"
        assert placeholder.description == "Test placeholder"


class TestPlaceholdersRegistry:
    """Tests for the PLACEHOLDERS registry."""

    def test_placeholders_registry_exists(self):
        """Test that PLACEHOLDERS registry is defined."""
        assert PLACEHOLDERS is not None
        assert isinstance(PLACEHOLDERS, list)
        assert len(PLACEHOLDERS) >= 2  # At least USERNAME and SID

    def test_placeholders_have_required_fields(self):
        """Test that all placeholders have required fields."""
        for placeholder in PLACEHOLDERS:
            assert placeholder.name
            assert placeholder.pattern
            assert placeholder.description
            assert placeholder.name.startswith("<")
            assert placeholder.name.endswith(">")

    def test_windows_username_placeholder(self):
        """Test that WINDOWS_USERNAME placeholder is defined correctly."""
        username_placeholder = next((p for p in PLACEHOLDERS if "USERNAME" in p.name), None)
        assert username_placeholder is not None
        assert username_placeholder.name == "<WINDOWS_USERNAME>"
        # Test pattern matches valid usernames
        pattern = re.compile(username_placeholder.pattern)
        assert pattern.match("john.doe")
        assert pattern.match("administrator")
        assert pattern.match("user123")

    def test_windows_sid_placeholder(self):
        """Test that WINDOWS_SECURITY_IDENTIFIER placeholder is defined correctly."""
        sid_placeholder = next((p for p in PLACEHOLDERS if "SECURITY_IDENTIFIER" in p.name), None)
        assert sid_placeholder is not None
        assert sid_placeholder.name == "<WINDOWS_SECURITY_IDENTIFIER>"
        # Test pattern matches valid SIDs
        pattern = re.compile(sid_placeholder.pattern)
        assert pattern.match("S-1-5-21-1234567890-1234567890-1234567890-1000")
        assert pattern.match("S-1-5-18")  # SYSTEM
        assert pattern.match("S-1-5-19")  # LOCAL SERVICE
        assert pattern.match("S-1-5-20")  # NETWORK SERVICE

    def test_windows_machine_guid_placeholder(self):
        """Test that WINDOWS_MACHINE_GUID placeholder is defined correctly."""
        uuid_placeholder = next((p for p in PLACEHOLDERS if "WINDOWS_MACHINE_GUID" in p.name), None)
        assert uuid_placeholder is not None
        assert uuid_placeholder.name == "<WINDOWS_MACHINE_GUID>"
        # Test pattern matches valid UUIDs
        pattern = re.compile(uuid_placeholder.pattern)
        assert pattern.match("f26c165b-53c8-414e-8abb-ec5f0f52df22")
        assert pattern.match("550e8400-e29b-41d4-a716-446655440000")
        assert pattern.match("ABCDEF12-3456-7890-ABCD-EF1234567890")  # Mixed case
        # Test pattern rejects invalid formats
        assert not pattern.match("invalid-uuid")
        assert not pattern.match("f26c165b53c8414e8abbec5f0f52df22")  # No hyphens


class TestConvertPlaceholderToRegex:
    """Tests for _convert_placeholder_to_regex method."""

    def setup_method(self):
        """Setup test fixtures."""
        self.db_service = MagicMock()
        self.resolver = PlaceholderResolver(self.db_service)

    def test_convert_single_placeholder(self):
        """Test converting a template with a single placeholder."""
        template = "/C:/Users/<WINDOWS_USERNAME>/AppData/file.txt"
        pattern = self.resolver._convert_placeholder_to_regex(template)

        assert pattern is not None
        assert pattern.match("/C:/Users/john.doe/AppData/file.txt")
        assert pattern.match("/C:/Users/administrator/AppData/file.txt")
        assert not pattern.match("/C:/Users/AppData/file.txt")  # Missing username

    def test_convert_multiple_placeholders(self):
        """Test converting a template with multiple placeholders."""
        template = "/C:/Users/<WINDOWS_USERNAME>/AppData/Roaming/Microsoft/Protect/<WINDOWS_SECURITY_IDENTIFIER>/abc123"
        pattern = self.resolver._convert_placeholder_to_regex(template)

        assert pattern is not None
        assert pattern.match(
            "/C:/Users/john.doe/AppData/Roaming/Microsoft/Protect/S-1-5-21-1234567890-1234567890-1234567890-1000/abc123"
        )

    def test_convert_case_insensitive(self):
        """Test that pattern matching is case-insensitive."""
        template = "/C:/Users/<WINDOWS_USERNAME>/AppData/file.txt"
        pattern = self.resolver._convert_placeholder_to_regex(template)

        assert pattern is not None
        # Test different case variations
        assert pattern.match("/C:/Users/john.doe/AppData/file.txt")
        assert pattern.match("/c:/users/john.doe/appdata/file.txt")
        assert pattern.match("/C:/USERS/JOHN.DOE/APPDATA/FILE.TXT")

    def test_convert_escape_special_chars(self):
        """Test that regex special characters are properly escaped."""
        template = "/C:/Users/<WINDOWS_USERNAME>/AppData/Local/file.txt"
        pattern = self.resolver._convert_placeholder_to_regex(template)

        assert pattern is not None
        # Periods should be escaped
        assert pattern.match("/C:/Users/john.doe/AppData/Local/file.txt")
        # Should not match without proper extension due to escaped period
        assert not pattern.match("/C:/Users/john.doe/AppData/Local/fileXtxt")

    def test_convert_no_placeholders(self):
        """Test converting a template with no placeholders returns None."""
        template = "/C:/Users/john.doe/AppData/file.txt"
        pattern = self.resolver._convert_placeholder_to_regex(template)

        assert pattern is None

    def test_convert_empty_string(self):
        """Test converting an empty string returns None."""
        pattern = self.resolver._convert_placeholder_to_regex("")

        assert pattern is None


class TestReplacePlaceholdersWithCaptures:
    """Tests for _replace_placeholders_with_captures method."""

    def setup_method(self):
        """Setup test fixtures."""
        self.db_service = MagicMock()
        self.resolver = PlaceholderResolver(self.db_service)

    def test_replace_username_placeholder(self):
        """Test replacing USERNAME placeholder with captured value."""
        template = "/C:/Users/<WINDOWS_USERNAME>/AppData/file.txt"
        pattern = self.resolver._convert_placeholder_to_regex(template)
        assert pattern is not None
        match = pattern.match("/C:/Users/john.doe/AppData/file.txt")
        assert match is not None

        result = self.resolver._replace_placeholders_with_captures(template, match)

        assert result == "/C:/Users/john.doe/AppData/file.txt"

    def test_replace_sid_placeholder(self):
        """Test replacing SID placeholder with captured value."""
        template = "/C:/Windows/System32/Microsoft/Protect/<WINDOWS_SECURITY_IDENTIFIER>/abc123"
        pattern = self.resolver._convert_placeholder_to_regex(template)
        assert pattern is not None
        match = pattern.match("/C:/Windows/System32/Microsoft/Protect/S-1-5-18/abc123")
        assert match is not None

        result = self.resolver._replace_placeholders_with_captures(template, match)

        assert result == "/C:/Windows/System32/Microsoft/Protect/S-1-5-18/abc123"

    def test_replace_multiple_placeholders(self):
        """Test replacing multiple placeholders in the same path."""
        template = "/C:/Users/<WINDOWS_USERNAME>/AppData/Roaming/Microsoft/Protect/<WINDOWS_SECURITY_IDENTIFIER>/abc123"
        pattern = self.resolver._convert_placeholder_to_regex(template)
        assert pattern is not None
        match = pattern.match(
            "/C:/Users/john.doe/AppData/Roaming/Microsoft/Protect/S-1-5-21-1234567890-1234567890-1234567890-1000/abc123"
        )
        assert match is not None

        result = self.resolver._replace_placeholders_with_captures(template, match)

        expected = (
            "/C:/Users/john.doe/AppData/Roaming/Microsoft/Protect/S-1-5-21-1234567890-1234567890-1234567890-1000/abc123"
        )
        assert result == expected



@pytest.mark.asyncio
class TestTryResolvePlaceholderPath:
    """Tests for try_resolve_placeholder_path method (backward resolution)."""

    def setup_method(self):
        """Setup test fixtures."""
        self.db_service = MagicMock()
        # Methods used by PlaceholderResolver
        self.db_service.get_placeholder_entries = AsyncMock()
        self.db_service.get_collected_files = AsyncMock()
        self.db_service.update_file_listing_path = AsyncMock(return_value=True)
        self.db_service.update_file_linking_path = AsyncMock(return_value=True)
        # Additional methods for completeness (not currently used by PlaceholderResolver)
        self.db_service.add_file_listing = AsyncMock(return_value=True)
        self.db_service.add_file_linking = AsyncMock(return_value=True)
        self.resolver = PlaceholderResolver(self.db_service)

    async def test_resolve_backward_full_path(self):
        """Test backward resolution with full path."""
        # Setup: Real file already exists in DB
        self.db_service.get_collected_files.return_value = [
            "/C:/Users/john.doe/AppData/Roaming/file.txt",
        ]

        # Placeholder path is being created
        placeholder_path = "/C:/Users/<WINDOWS_USERNAME>/AppData/Roaming/file.txt"
        source = "test-source"

        result = await self.resolver.try_resolve_placeholder_path(source, placeholder_path)

        assert result == "/C:/Users/john.doe/AppData/Roaming/file.txt"

    async def test_resolve_backward_bare_filename(self):
        """Test backward resolution with bare filename."""
        # Setup: Real bare filename already exists
        self.db_service.get_collected_files.return_value = ["Local State"]

        # Placeholder path being created
        placeholder_path = "/C:/Users/<WINDOWS_USERNAME>/AppData/Local/Google/Chrome/User Data/Local State"
        source = "test-source"

        result = await self.resolver.try_resolve_placeholder_path(source, placeholder_path)

        # Cannot match bare filename against full placeholder path
        assert result is None

    async def test_resolve_backward_no_match(self):
        """Test backward resolution with no matching file."""
        self.db_service.get_collected_files.return_value = [
            "/C:/Users/jane.doe/different/path.txt",
        ]

        placeholder_path = "/C:/Users/<WINDOWS_USERNAME>/AppData/file.txt"
        source = "test-source"

        result = await self.resolver.try_resolve_placeholder_path(source, placeholder_path)

        assert result is None

    async def test_resolve_backward_no_collected_files(self):
        """Test backward resolution when no collected files exist."""
        self.db_service.get_collected_files.return_value = []

        placeholder_path = "/C:/Users/<WINDOWS_USERNAME>/AppData/file.txt"
        source = "test-source"

        result = await self.resolver.try_resolve_placeholder_path(source, placeholder_path)

        assert result is None

    async def test_resolve_backward_no_placeholders(self):
        """Test backward resolution with path containing no placeholders."""
        placeholder_path = "/C:/Users/john.doe/AppData/file.txt"
        source = "test-source"

        result = await self.resolver.try_resolve_placeholder_path(source, placeholder_path)

        assert result is None
        self.db_service.get_collected_files.assert_not_called()


@pytest.mark.asyncio
class TestPlaceholderResolutionScenarios:
    """Integration-style tests for complete placeholder resolution scenarios."""

    def setup_method(self):
        """Setup test fixtures."""
        self.db_service = MagicMock()
        # Methods used by PlaceholderResolver
        self.db_service.get_placeholder_entries = AsyncMock()
        self.db_service.get_collected_files = AsyncMock()
        self.db_service.update_file_listing_path = AsyncMock(return_value=True)
        self.db_service.update_file_linking_path = AsyncMock(return_value=True)
        # Additional methods for completeness (not currently used by PlaceholderResolver)
        self.db_service.add_file_listing = AsyncMock(return_value=True)
        self.db_service.add_file_linking = AsyncMock(return_value=True)
        self.resolver = PlaceholderResolver(self.db_service)

    async def test_chromium_masterkey_resolution(self):
        """Test resolution of Chromium masterkey placeholder."""
        # Scenario: Local State creates placeholder for masterkey,
        # then real masterkey file arrives
        placeholder_path = (
            "/C:/Users/<WINDOWS_USERNAME>/AppData/Roaming/Microsoft/Protect/"
            "<WINDOWS_SECURITY_IDENTIFIER>/abc-123-def-456"
        )

        self.db_service.get_placeholder_entries.return_value = [
            {
                "table_name": "file_listings",
                "path": placeholder_path,
            }
        ]

        # Real masterkey arrives
        real_path = (
            "/C:/Users/john.doe/AppData/Roaming/Microsoft/Protect/"
            "S-1-5-21-1234567890-1234567890-1234567890-1000/abc-123-def-456"
        )
        source = "test-agent"

        count = await self.resolver.resolve_placeholders_for_file(real_path, source)

        assert count == 1
        call_args = self.db_service.update_file_listing_path.call_args
        assert call_args[0][0] == source
        assert call_args[0][1] == placeholder_path
        assert call_args[0][2] == real_path

    async def test_case_insensitive_resolution(self):
        """Test that resolution works with different case variations."""
        placeholder_path = "/C:/Users/<WINDOWS_USERNAME>/AppData/file.txt"
        self.db_service.get_placeholder_entries.return_value = [
            {"table_name": "file_listings", "path": placeholder_path}
        ]

        # Real file with different case
        real_path = "/c:/users/john.doe/appdata/file.txt"
        source = "test-source"

        count = await self.resolver.resolve_placeholders_for_file(real_path, source)

        assert count == 1

    async def test_extensibility_new_placeholder(self):
        """Test that adding a new placeholder to registry works."""
        # This test verifies the extensibility claim - just check that we can
        # read the PLACEHOLDERS registry and it's used
        assert len(PLACEHOLDERS) >= 2

        # Verify the registry is used
        placeholder_names = [p.name for p in PLACEHOLDERS]
        assert "<WINDOWS_USERNAME>" in placeholder_names
        assert "<WINDOWS_SECURITY_IDENTIFIER>" in placeholder_names

    async def test_cng_system_private_key_forward_resolution(self):
        """Test forward resolution of CNG system private key path with UUID placeholder."""
        # Scenario: Chrome Local State creates placeholder for CNG system private key,
        # then real key file arrives (forward propagation)
        placeholder_path = (
            "/C:/ProgramData/Microsoft/Crypto/SystemKeys/7096db7aeb75c0d3497ecd56d355a695_<WINDOWS_MACHINE_GUID>"
        )

        self.db_service.get_placeholder_entries.return_value = [
            {
                "table_name": "file_linkings",
                "path": placeholder_path,
            }
        ]

        # Real CNG system private key file arrives
        real_path = "/C:/ProgramData/Microsoft/Crypto/SystemKeys/7096db7aeb75c0d3497ecd56d355a695_f26c165b-53c8-414e-8abb-ec5f0f52df22"
        source = "test-agent"

        count = await self.resolver.resolve_placeholders_for_file(real_path, source)

        assert count == 1
        call_args = self.db_service.update_file_linking_path.call_args
        assert call_args[0][0] == source
        assert call_args[0][1] == placeholder_path
        assert call_args[0][2] == real_path

    async def test_cng_system_private_key_backward_resolution(self):
        """Test backward resolution of CNG system private key path with UUID placeholder."""
        # Scenario: Real key file already exists in DB, then Chrome Local State
        # tries to create placeholder entry (backward propagation)

        # Real CNG system private key file already collected
        real_path = "/C:/ProgramData/Microsoft/Crypto/SystemKeys/7096db7aeb75c0d3497ecd56d355a695_f26c165b-53c8-414e-8abb-ec5f0f52df22"
        self.db_service.get_collected_files.return_value = [real_path]

        # Placeholder path being created
        placeholder_path = (
            "/C:/ProgramData/Microsoft/Crypto/SystemKeys/7096db7aeb75c0d3497ecd56d355a695_<WINDOWS_MACHINE_GUID>"
        )
        source = "test-agent"

        result = await self.resolver.try_resolve_placeholder_path(source, placeholder_path)

        # Should return the real path instead of None
        assert result == real_path
        self.db_service.get_collected_files.assert_called_once_with(source)
