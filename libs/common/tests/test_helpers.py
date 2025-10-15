"""Tests for chromium.local_state module."""

from common.helpers import get_drive_from_path


class TestGetDriveFromPath:
    """Test suite for get_drive_from_path function."""

    def test_valid_path_with_colon(self):
        """Test valid path with colon in drive letter."""
        assert get_drive_from_path("/C:/Users/test") == "/C:"
        assert get_drive_from_path("/D:/Program Files") == "/D:"
        assert get_drive_from_path("/E:/temp") == "/E:"

    def test_invalid_path_without_colon(self):
        """Test invalid path without colon in drive letter - should fail."""
        assert get_drive_from_path("/C/Users/test") is None
        assert get_drive_from_path("/D/Program Files") is None
        assert get_drive_from_path("/E/temp") is None

    def test_lowercase_drive_letters(self):
        """Test lowercase drive letters are preserved."""
        assert get_drive_from_path("/c:/Users/test") == "/c:"
        assert get_drive_from_path("/d:/temp") == "/d:"

    def test_mixed_case_drive_letters(self):
        """Test mixed case scenarios."""
        assert get_drive_from_path("/C:/Users/test") == "/C:"
        assert get_drive_from_path("/c:/Users/test") == "/c:"

    def test_all_valid_drive_letters(self):
        """Test all valid drive letters A-Z with colon."""
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            assert get_drive_from_path(f"/{letter}:/Users") == f"/{letter}:"
            # Without colon should fail
            assert get_drive_from_path(f"/{letter}/Users") is None

    def test_invalid_numeric_drive(self):
        """Test invalid numeric drive letters."""
        assert get_drive_from_path("/1:/Users/test") is None
        assert get_drive_from_path("/123/Users/test") is None
        assert get_drive_from_path("/0:/temp") is None

    def test_invalid_special_characters(self):
        """Test invalid special characters as drive."""
        assert get_drive_from_path("/$:/Users/test") is None
        assert get_drive_from_path("/@:/Users/test") is None
        assert get_drive_from_path("/#/Users/test") is None
        assert get_drive_from_path("/*/Users/test") is None

    def test_invalid_multiple_letters(self):
        """Test invalid multiple letters without colon."""
        assert get_drive_from_path("/AB/Users/test") is None
        assert get_drive_from_path("/CD:/Users/test") is None
        assert get_drive_from_path("/ABC/Users/test") is None

    def test_invalid_colon_usage(self):
        """Test invalid colon usage."""
        assert get_drive_from_path("/C;/Users/test") is None  # semicolon instead
        assert get_drive_from_path("/C::/Users/test") is None  # double colon
        assert get_drive_from_path("/:C/Users/test") is None  # colon before letter

    def test_path_without_leading_slash(self):
        """Test paths without leading slash."""
        assert get_drive_from_path("C:/Users/test") == "C:"
        assert get_drive_from_path("C/Users/test") is None

    def test_path_with_only_drive(self):
        """Test paths with only drive letter."""
        assert get_drive_from_path("/C:") == "/C:"
        assert get_drive_from_path("/C") is None  # Without colon should fail
        assert get_drive_from_path("/D:") == "/D:"

    def test_path_with_trailing_elements(self):
        """Test various path structures."""
        assert get_drive_from_path("/C:/Users/test/Documents/file.txt") == "/C:"
        assert get_drive_from_path("/C/Users/test/Documents/file.txt") is None  # Without colon should fail
        assert get_drive_from_path("/D:/Program Files/App/config.ini") == "/D:"

    def test_edge_case_single_slash(self):
        """Test edge case of single slash."""
        assert get_drive_from_path("/") is None

    def test_edge_case_double_slash(self):
        """Test edge case of double slash."""
        assert get_drive_from_path("//") is None
        assert get_drive_from_path("//C/Users") is None

    def test_path_with_spaces(self):
        """Test paths with spaces in directories."""
        assert get_drive_from_path("/C:/Program Files/Test") == "/C:"
        assert get_drive_from_path("/C/Program Files/Test") is None  # Without colon should fail

    def test_mixed_slashes_in_path(self):
        """Test that function handles forward slashes correctly."""
        # The function expects POSIX-style paths with forward slashes
        assert get_drive_from_path("/C:/Users/test") == "/C:"
        assert get_drive_from_path("/C/Users/test") is None  # Without colon should fail

    def test_unicode_characters(self):
        """Test paths with unicode characters in later parts."""
        assert get_drive_from_path("/C:/Users/тест") == "/C:"
        assert get_drive_from_path("/C/Users/测试") is None  # Without colon should fail

    def test_empty_drive_after_slash(self):
        """Test path with empty drive section."""
        assert get_drive_from_path("//Users/test") is None

    def test_real_world_chrome_paths(self):
        """Test with real-world Chrome Local State paths."""
        assert get_drive_from_path("/C:/Users/itadmin/AppData/Local/Google/Chrome/User Data/Local State") == "/C:"
        assert get_drive_from_path("/C/Users/itadmin/AppData/Local/Google/Chrome/User Data/Local State") is None  # Without colon should fail
        assert get_drive_from_path("/C/DPAPIUser/AppData/Local/Google/Chrome/User Data/Local State") is None  # Without colon should fail

    def test_alternate_browser_paths(self):
        """Test with other Chromium-based browser paths."""
        assert get_drive_from_path("/D:/Users/test/AppData/Local/Microsoft/Edge/User Data/Local State") == "/D:"
        assert get_drive_from_path("/E/Users/test/AppData/Local/BraveSoftware/Brave-Browser/User Data/Local State") is None  # Without colon should fail
