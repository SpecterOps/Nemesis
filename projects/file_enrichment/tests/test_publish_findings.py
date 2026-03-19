"""Tests for publish_findings alert building, specifically raw_data JSON parsing."""

import json


class TestRawDataParsing:
    """Test that raw_data from asyncpg (which may be a JSON string) is handled correctly."""

    def _extract_titus_info(self, raw_data):
        """Simulate the raw_data processing logic from publish_alerts_for_findings."""
        if isinstance(raw_data, str):
            raw_data = json.loads(raw_data)

        rule_message = ""
        validation_message = ""
        try:
            if raw_data and "match" in raw_data and "rule_name" in raw_data["match"]:
                rule_name = raw_data["match"]["rule_name"]
                rule_id = raw_data["match"].get("rule_id", "")
                rule_id_suffix = f" (`{rule_id}`)" if rule_id else ""
                rule_message = f"- *Rule name:* {rule_name}{rule_id_suffix}\n"
            if raw_data and "match" in raw_data and raw_data["match"].get("validation_result"):
                vr = raw_data["match"]["validation_result"]
                status = vr.get("status", "undetermined")
                status_label = {
                    "valid": "CONFIRMED ACTIVE",
                    "invalid": "INACTIVE",
                    "undetermined": "UNVERIFIED",
                }.get(status, "UNVERIFIED")
                validation_message = f"- *Validation:* {status_label}\n"
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

        return rule_message, validation_message

    def test_raw_data_as_dict(self):
        """raw_data already parsed as dict (normal case)."""
        raw_data = {
            "match": {
                "rule_name": "AWS Access Key",
                "rule_id": "aws-key-001",
                "validation_result": {"status": "valid"},
            }
        }
        rule_msg, val_msg = self._extract_titus_info(raw_data)
        assert "AWS Access Key" in rule_msg
        assert "aws-key-001" in rule_msg
        assert "CONFIRMED ACTIVE" in val_msg

    def test_raw_data_as_json_string(self):
        """raw_data as JSON string (asyncpg returning string for JSONB after json.dumps INSERT)."""
        raw_data_dict = {
            "match": {
                "rule_name": "GitHub Token",
                "rule_id": "gh-token-001",
                "validation_result": {"status": "invalid"},
            }
        }
        raw_data = json.dumps(raw_data_dict)
        rule_msg, val_msg = self._extract_titus_info(raw_data)
        assert "GitHub Token" in rule_msg
        assert "INACTIVE" in val_msg

    def test_raw_data_as_json_string_without_match(self):
        """raw_data as JSON string but no 'match' key — should not error."""
        raw_data = json.dumps({"some_other_key": "value"})
        rule_msg, val_msg = self._extract_titus_info(raw_data)
        assert rule_msg == ""
        assert val_msg == ""

    def test_raw_data_none(self):
        """raw_data is None — should not error."""
        rule_msg, val_msg = self._extract_titus_info(None)
        assert rule_msg == ""
        assert val_msg == ""

    def test_raw_data_empty_dict(self):
        """raw_data is empty dict."""
        rule_msg, val_msg = self._extract_titus_info({})
        assert rule_msg == ""
        assert val_msg == ""

    def test_raw_data_double_encoded_json(self):
        """raw_data double-encoded (json.dumps of a json string) — should handle gracefully."""
        raw_data_dict = {"match": {"rule_name": "Test Rule"}}
        double_encoded = json.dumps(json.dumps(raw_data_dict))
        # After one json.loads, it's still a string; should be caught by except
        rule_msg, val_msg = self._extract_titus_info(double_encoded)
        # After first parse it's a string, second "match" in raw_data does substring,
        # then raw_data["match"] raises TypeError, caught by except clause
        assert rule_msg == ""
        assert val_msg == ""

    def test_raw_data_with_validation_undetermined(self):
        """raw_data with undetermined validation status."""
        raw_data = json.dumps(
            {"match": {"rule_name": "Slack Token", "validation_result": {"status": "undetermined"}}}
        )
        rule_msg, val_msg = self._extract_titus_info(raw_data)
        assert "Slack Token" in rule_msg
        assert "UNVERIFIED" in val_msg
