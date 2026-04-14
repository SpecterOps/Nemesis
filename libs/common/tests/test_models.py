"""Tests for Pydantic models in common.models."""

from common.models import ScanResults, ScanStats


def test_scan_results_null_matches_defaults_to_empty_list():
    """Regression test for issue #117: ScanResults must accept null/missing
    matches and default to an empty list instead of raising a validation error."""
    result = ScanResults(
        scan_duration_ms=100,
        bytes_scanned=1024,
        matches=None,
        stats=ScanStats(
            blobs_seen=1,
            blobs_scanned=1,
            bytes_seen=1024,
            bytes_scanned=1024,
            matches_found=0,
        ),
        scan_type="regular",
    )
    assert result.matches == []


def test_scan_results_missing_matches_defaults_to_empty_list():
    """ScanResults with no matches field should default to []."""
    result = ScanResults(
        scan_duration_ms=50,
        bytes_scanned=512,
        stats=ScanStats(
            blobs_seen=1,
            blobs_scanned=1,
            bytes_seen=512,
            bytes_scanned=512,
            matches_found=0,
        ),
    )
    assert result.matches == []
