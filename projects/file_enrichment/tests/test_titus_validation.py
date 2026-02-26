"""Tests for Titus validation result handling."""

import sys
from unittest.mock import MagicMock

from common.models import MatchInfo, MatchLocation, ValidationResult

# Mock the global_vars module to avoid Dapr initialization during import
sys.modules["file_enrichment.global_vars"] = MagicMock()

from file_enrichment.subscriptions.titus import create_finding_summary  # noqa: E402


class TestValidationResult:
    """Test the ValidationResult model."""

    def test_default_values(self):
        vr = ValidationResult()
        assert vr.status == "undetermined"
        assert vr.confidence == 0.0
        assert vr.message is None
        assert vr.validated_at is None
        assert vr.details is None
        assert vr.is_valid is False

    def test_valid_status(self):
        vr = ValidationResult(status="valid", confidence=0.95)
        assert vr.is_valid is True

    def test_invalid_status(self):
        vr = ValidationResult(status="invalid", confidence=1.0, message="Token expired")
        assert vr.is_valid is False
        assert vr.message == "Token expired"

    def test_undetermined_status(self):
        vr = ValidationResult(status="undetermined")
        assert vr.is_valid is False

    def test_full_model(self):
        vr = ValidationResult(
            status="valid",
            confidence=0.99,
            message="Key is active",
            validated_at="2025-06-15T10:30:00Z",
            details={"account_id": "123456789", "username": "testuser"},
        )
        assert vr.is_valid is True
        assert vr.confidence == 0.99
        assert vr.validated_at == "2025-06-15T10:30:00Z"
        assert vr.details["account_id"] == "123456789"

    def test_serialization_roundtrip(self):
        vr = ValidationResult(status="valid", confidence=0.9, message="Active")
        data = vr.model_dump()
        vr2 = ValidationResult(**data)
        assert vr2.status == "valid"
        assert vr2.confidence == 0.9
        assert vr2.is_valid is True


class TestSeverityAdjustment:
    """Test severity adjustment based on validation status."""

    @staticmethod
    def _compute_severity(rule_name: str, rule_type: str, validation_result: ValidationResult | None) -> int:
        """Reproduce the severity logic from store_titus_results."""
        severity = 7
        if rule_type == "secret" and "generic secret" in rule_name.lower():
            severity = 4

        if validation_result:
            if validation_result.status == "valid":
                severity = 9
                if rule_type == "secret" and "generic secret" in rule_name.lower():
                    severity = 7
            elif validation_result.status == "invalid":
                severity = max(severity - 3, 2)

        return severity

    def test_specific_secret_no_validation(self):
        assert self._compute_severity("AWS Access Key", "secret", None) == 7

    def test_generic_secret_no_validation(self):
        assert self._compute_severity("Generic Secret", "secret", None) == 4

    def test_specific_secret_valid(self):
        vr = ValidationResult(status="valid", confidence=0.95)
        assert self._compute_severity("AWS Access Key", "secret", vr) == 9

    def test_generic_secret_valid(self):
        vr = ValidationResult(status="valid", confidence=0.8)
        assert self._compute_severity("Generic Secret", "secret", vr) == 7

    def test_specific_secret_invalid(self):
        vr = ValidationResult(status="invalid", confidence=1.0)
        assert self._compute_severity("AWS Access Key", "secret", vr) == 4

    def test_generic_secret_invalid(self):
        vr = ValidationResult(status="invalid", confidence=1.0)
        assert self._compute_severity("Generic Secret", "secret", vr) == 2

    def test_specific_secret_undetermined(self):
        vr = ValidationResult(status="undetermined")
        assert self._compute_severity("AWS Access Key", "secret", vr) == 7

    def test_generic_secret_undetermined(self):
        vr = ValidationResult(status="undetermined")
        assert self._compute_severity("Generic Secret", "secret", vr) == 4


class TestFindingSummaryRuleID:
    """Test that rule_id appears in finding summaries."""

    @staticmethod
    def _make_match(rule_id: str | None = None) -> MatchInfo:
        return MatchInfo(
            rule_name="AWS Access Key",
            rule_id=rule_id,
            rule_type="secret",
            matched_content="AKIA1234567890ABCDEF",
            location=MatchLocation(line=10, column=5),
            snippet="aws_key = AKIA1234567890ABCDEF",
        )

    def test_rule_id_in_summary(self):
        match = self._make_match(rule_id="np.aws.1")
        summary = create_finding_summary(match)
        assert "**Rule ID**: `np.aws.1`" in summary

    def test_no_rule_id_when_none(self):
        match = self._make_match(rule_id=None)
        summary = create_finding_summary(match)
        assert "Rule ID" not in summary

    def test_no_rule_id_when_empty(self):
        match = self._make_match(rule_id="")
        summary = create_finding_summary(match)
        assert "Rule ID" not in summary


class TestFindingSummaryValidation:
    """Test that validation results appear in finding summaries."""

    @staticmethod
    def _make_match(validation_result: ValidationResult | None = None) -> MatchInfo:
        return MatchInfo(
            rule_name="AWS Access Key",
            rule_type="secret",
            matched_content="AKIA1234567890ABCDEF",
            location=MatchLocation(line=10, column=5),
            snippet="aws_key = AKIA1234567890ABCDEF",
            validation_result=validation_result,
        )

    def test_no_validation_section_when_none(self):
        match = self._make_match(None)
        summary = create_finding_summary(match)
        assert "Validation Result" not in summary

    def test_valid_shows_confirmed_active(self):
        vr = ValidationResult(status="valid", confidence=0.95, message="Key is active")
        match = self._make_match(vr)
        summary = create_finding_summary(match)
        assert "### Validation Result" in summary
        assert "CONFIRMED ACTIVE" in summary
        assert "95%" in summary
        assert "Key is active" in summary

    def test_invalid_shows_inactive(self):
        vr = ValidationResult(status="invalid", confidence=1.0)
        match = self._make_match(vr)
        summary = create_finding_summary(match)
        assert "INACTIVE" in summary

    def test_undetermined_shows_unverified(self):
        vr = ValidationResult(status="undetermined")
        match = self._make_match(vr)
        summary = create_finding_summary(match)
        assert "UNVERIFIED" in summary

    def test_details_included(self):
        vr = ValidationResult(
            status="valid",
            confidence=0.99,
            details={"account_id": "123456789", "username": "testuser"},
        )
        match = self._make_match(vr)
        summary = create_finding_summary(match)
        assert "account_id: 123456789" in summary
        assert "username: testuser" in summary
