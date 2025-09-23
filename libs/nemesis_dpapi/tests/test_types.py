"""Pytest tests for Windows SID validation."""

import pytest
from nemesis_dpapi.types import Sid, validate_windows_sid
from pydantic import BaseModel, ValidationError


class TestSidValidation:
    """Test cases for Windows SID validation."""

    class SidTestType(BaseModel):
        sid: Sid

    def test_valid_sids(self):
        """Test valid Windows SID formats."""
        valid_sids = [
            "S-1-5-21-1234567890-1234567890-1234567890-1001",  # Domain user
            "S-1-5-18",  # Local system
            "S-1-5-32-544",  # Builtin administrators
            "S-1-5-21-0-0-0-500",  # Domain administrator
            "S-1-1-0",  # Everyone
            "S-1-5-4",  # Interactive
        ]

        for sid in valid_sids:
            # Test direct validation function
            validated = validate_windows_sid(sid)
            assert validated == sid

            # Test Pydantic type annotation
            t = self.SidTestType(sid=sid)
            assert t.sid == sid

    def test_invalid_sids(self):
        """Test invalid Windows SID formats."""
        invalid_sids = [
            "not-a-sid",
            "S-2-5-21-1234567890-1234567890-1234567890-1001",  # Wrong revision
            "S-1",  # Too short
            "S-1-5",  # Missing subauthority
            "S-1-5-abc",  # Non-numeric subauthority
            "S-1--5-21-1001",  # Empty component
            "S-1-5-21--1001",  # Empty component
            "",  # Empty string
            "1-5-21-1001",  # Missing S prefix
            "S-1-5-21-1234567890-1234567890-1234567890-1001-",  # Trailing dash
            "S-1-5--21-1001",  # Double dash
        ]

        for sid in invalid_sids:
            with pytest.raises(ValueError, match="Invalid|SID"):
                validate_windows_sid(sid)

            with pytest.raises(ValidationError):
                self.SidTestType(sid=sid)

    def test_sid_type_annotation(self):
        """Test that Sid type annotation works correctly."""

        # Valid SID should work
        valid_sid = "S-1-5-21-1234567890-1234567890-1234567890-1001"
        t = self.SidTestType(sid=valid_sid)
        assert t.sid == valid_sid

        # Invalid SID should raise ValidationError
        with pytest.raises(ValidationError) as exc_info:
            self.SidTestType(sid="invalid-sid")

        assert "Invalid Windows SID format" in str(exc_info.value)

    def test_sid_revision_validation(self):
        """Test that only revision 1 is accepted."""
        with pytest.raises(ValueError, match="SID revision must be 1"):
            validate_windows_sid("S-2-5-21-1234567890-1234567890-1234567890-1001")

    def test_sid_non_string_input(self):
        """Test that non-string inputs are rejected."""
        with pytest.raises(ValueError, match="SID must be a string"):
            validate_windows_sid(123)

        with pytest.raises(ValueError, match="SID must be a string"):
            validate_windows_sid(None)
