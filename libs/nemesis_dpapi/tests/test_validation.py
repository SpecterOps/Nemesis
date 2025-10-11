"""Tests for validation helpers."""

import pytest
from Crypto.Hash import SHA1

from nemesis_dpapi.validation import (
    check_write_once_conflicts,
    validate_and_calculate_sha1,
    validate_no_empty_string,
)


class TestValidateAndCalculateSha1:
    """Test SHA1 validation and calculation."""

    def test_calculate_sha1_when_only_plaintext_provided(self):
        """Should calculate SHA1 when only plaintext_key is provided."""
        plaintext_key = b"my_secret_key"
        expected_sha1 = SHA1.new(plaintext_key).digest()

        result = validate_and_calculate_sha1(plaintext_key, None)

        assert result == expected_sha1

    def test_validate_matching_sha1(self):
        """Should accept when provided SHA1 matches calculated SHA1."""
        plaintext_key = b"my_secret_key"
        correct_sha1 = SHA1.new(plaintext_key).digest()

        result = validate_and_calculate_sha1(plaintext_key, correct_sha1)

        assert result == correct_sha1

    def test_reject_mismatched_sha1(self):
        """Should raise ValueError when provided SHA1 doesn't match calculated."""
        plaintext_key = b"my_secret_key"
        wrong_sha1 = b"0" * 20  # Incorrect SHA1

        with pytest.raises(ValueError, match="does not match calculated SHA1"):
            validate_and_calculate_sha1(plaintext_key, wrong_sha1)

    def test_accept_sha1_only_update(self):
        """Should accept when only SHA1 is provided (valid scenario)."""
        sha1_only = b"1" * 20

        result = validate_and_calculate_sha1(None, sha1_only)

        assert result == sha1_only

    def test_return_none_when_both_none(self):
        """Should return None when both inputs are None."""
        result = validate_and_calculate_sha1(None, None)

        assert result is None


class TestValidateNoEmptyString:
    """Test empty string validation."""

    def test_accept_none(self):
        """Should accept None (unset value)."""
        validate_no_empty_string(None, "test_field")  # Should not raise

    def test_accept_non_empty_string(self):
        """Should accept non-empty strings."""
        validate_no_empty_string("DC01.contoso.com", "domain_controller")  # Should not raise

    def test_reject_empty_string(self):
        """Should reject empty strings."""
        with pytest.raises(ValueError, match="cannot be empty string"):
            validate_no_empty_string("", "domain_controller")

    def test_error_message_includes_field_name(self):
        """Should include field name in error message."""
        with pytest.raises(ValueError, match="domain_controller"):
            validate_no_empty_string("", "domain_controller")


class TestCheckWriteOnceConflicts:
    """Test write-once conflict detection."""

    class MockRecord:
        """Mock record for testing."""

        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

    def test_no_conflicts_when_existing_is_null(self):
        """Should allow writing to NULL fields."""
        existing = self.MockRecord(field1=None, field2=None)
        new = self.MockRecord(field1=b"value1", field2=b"value2")

        conflicts = check_write_once_conflicts(existing, new, ["field1", "field2"])

        assert conflicts == []

    def test_no_conflicts_when_values_match(self):
        """Should allow idempotent updates (same values)."""
        existing = self.MockRecord(field1=b"value1", field2=b"value2")
        new = self.MockRecord(field1=b"value1", field2=b"value2")

        conflicts = check_write_once_conflicts(existing, new, ["field1", "field2"])

        assert conflicts == []

    def test_conflict_when_trying_to_change_value(self):
        """Should detect conflict when trying to change non-NULL value."""
        existing = self.MockRecord(field1=b"old_value", field2=None)
        new = self.MockRecord(field1=b"new_value", field2=b"value2")

        conflicts = check_write_once_conflicts(existing, new, ["field1", "field2"])

        assert conflicts == ["field1"]

    def test_conflict_when_trying_to_clear_value(self):
        """Should detect conflict when trying to set value to NULL."""
        existing = self.MockRecord(field1=b"value1", field2=None)
        new = self.MockRecord(field1=None, field2=b"value2")

        conflicts = check_write_once_conflicts(existing, new, ["field1", "field2"])

        assert conflicts == ["field1"]

    def test_multiple_conflicts(self):
        """Should detect all conflicting fields."""
        existing = self.MockRecord(
            field1=b"value1",
            field2=b"value2",
            field3=b"value3",
        )
        new = self.MockRecord(
            field1=b"changed1",
            field2=b"value2",  # Same
            field3=b"changed3",
        )

        conflicts = check_write_once_conflicts(existing, new, ["field1", "field2", "field3"])

        assert set(conflicts) == {"field1", "field3"}

    def test_partial_update_allowed(self):
        """Should allow updating NULL fields while preserving non-NULL."""
        existing = self.MockRecord(
            field1=b"existing_value",
            field2=None,
            field3=None,
        )
        new = self.MockRecord(
            field1=b"existing_value",  # Same
            field2=b"new_value",  # NULL -> value (allowed)
            field3=None,  # NULL -> NULL (allowed)
        )

        conflicts = check_write_once_conflicts(existing, new, ["field1", "field2", "field3"])

        assert conflicts == []

    def test_empty_bytes_distinct_from_none(self):
        """Should treat empty bytes as distinct from None."""
        existing = self.MockRecord(field1=b"")
        new = self.MockRecord(field1=None)

        conflicts = check_write_once_conflicts(existing, new, ["field1"])

        assert conflicts == ["field1"]

    def test_empty_bytes_equality(self):
        """Should treat empty bytes as equal to empty bytes."""
        existing = self.MockRecord(field1=b"")
        new = self.MockRecord(field1=b"")

        conflicts = check_write_once_conflicts(existing, new, ["field1"])

        assert conflicts == []

    def test_string_fields(self):
        """Should work with string fields too."""
        existing = self.MockRecord(name="Alice", email=None)
        new = self.MockRecord(name="Bob", email="test@example.com")

        conflicts = check_write_once_conflicts(existing, new, ["name", "email"])

        assert conflicts == ["name"]

    def test_uuid_fields(self):
        """Should work with UUID fields."""
        from uuid import UUID

        guid1 = UUID("12345678-1234-5678-1234-567812345678")
        guid2 = UUID("87654321-4321-8765-4321-876543218765")

        existing = self.MockRecord(backup_key_guid=guid1)
        new = self.MockRecord(backup_key_guid=guid2)

        conflicts = check_write_once_conflicts(existing, new, ["backup_key_guid"])

        assert conflicts == ["backup_key_guid"]
