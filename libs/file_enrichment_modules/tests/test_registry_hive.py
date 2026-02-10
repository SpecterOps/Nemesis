# pyright: reportAttributeAccessIssue=false
"""Tests for the registry_hive enrichment module.

Test fixtures (SAM, SYSTEM, SECURITY hives) are from the NIST CFReDS project:
https://cfreds-archive.nist.gov/winreg/cfreds-2017-winreg/cfreds-2017-winreg.html
Dataset: cfreds-2017-winreg_sgrd-10
"""

import os
import struct
from unittest.mock import MagicMock, patch

import pytest
from file_enrichment_modules.registry_hive.analyzer import (
    EMPTY_LM_HASH,
    EMPTY_NT_HASH,
    RegistryHiveAnalyzer,
    _filetime_to_str,
    _regipy_value_to_bytes,
)

# Path to NIST CFReDS registry hive fixtures
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "registry_hives")
SAM_HIVE = os.path.join(FIXTURES_DIR, "SAM")
SYSTEM_HIVE = os.path.join(FIXTURES_DIR, "SYSTEM")
SECURITY_HIVE = os.path.join(FIXTURES_DIR, "SECURITY")


@pytest.fixture
def analyzer():
    """Create a RegistryHiveAnalyzer with mocked external dependencies."""
    with patch("file_enrichment_modules.registry_hive.analyzer.StorageMinio"):
        a = RegistryHiveAnalyzer()
        a.storage = MagicMock()
        a.asyncpg_pool = None
        return a


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestFiletimeToStr:
    def test_zero_returns_none(self):
        assert _filetime_to_str(0) is None

    def test_max_returns_none(self):
        assert _filetime_to_str(0x7FFFFFFFFFFFFFFF) is None

    def test_overflow_returns_none(self):
        assert _filetime_to_str(0xFFFFFFFFFFFFFFFF) is None

    def test_epoch_boundary_returns_none(self):
        # Exactly at the epoch diff (1970-01-01) or earlier
        EPOCH_DIFF = 116444736000000000
        assert _filetime_to_str(EPOCH_DIFF) is None
        assert _filetime_to_str(EPOCH_DIFF - 1) is None

    def test_known_timestamp(self):
        # 2016-03-22 20:55:15 UTC = FILETIME 131032353150000000 (approx)
        # Let's verify a round-trip with a known FILETIME
        # Jan 1, 2000 00:00:00 UTC = FILETIME 125911584000000000
        ft = 125911584000000000
        result = _filetime_to_str(ft)
        assert result == "2000-01-01 00:00:00 UTC"

    def test_returns_utc_string_format(self):
        # Any valid timestamp should end with " UTC"
        ft = 130000000000000000  # Some valid filetime
        result = _filetime_to_str(ft)
        assert result is not None
        assert result.endswith(" UTC")


class TestRegipyValueToBytes:
    def test_bytes_passthrough(self):
        data = b"\x01\x02\x03"
        assert _regipy_value_to_bytes(data) == data

    def test_hex_string_conversion(self):
        assert _regipy_value_to_bytes("0102030405") == b"\x01\x02\x03\x04\x05"

    def test_invalid_hex_returns_none(self):
        assert _regipy_value_to_bytes("not_hex") is None

    def test_int_returns_none(self):
        assert _regipy_value_to_bytes(42) is None

    def test_none_returns_none(self):
        assert _regipy_value_to_bytes(None) is None

    def test_empty_string(self):
        assert _regipy_value_to_bytes("") == b""

    def test_empty_bytes(self):
        assert _regipy_value_to_bytes(b"") == b""


# ---------------------------------------------------------------------------
# SAM user metadata extraction tests (using real NIST CFReDS hive fixtures)
# ---------------------------------------------------------------------------


class TestGetSamUserMetadata:
    """Test _get_sam_user_metadata using real NIST CFReDS SAM hive."""

    def test_returns_metadata_for_known_rids(self, analyzer):
        metadata = analyzer._get_sam_user_metadata(SAM_HIVE)
        # CFReDS SAM has at least these RIDs
        assert 500 in metadata  # Administrator
        assert 501 in metadata  # Guest
        assert 1000 in metadata  # IEUser
        assert 1003 in metadata  # CFTT

    def test_administrator_is_disabled(self, analyzer):
        metadata = analyzer._get_sam_user_metadata(SAM_HIVE)
        admin = metadata[500]
        assert admin["account_disabled"] is True

    def test_guest_is_disabled(self, analyzer):
        metadata = analyzer._get_sam_user_metadata(SAM_HIVE)
        guest = metadata[501]
        assert guest["account_disabled"] is True

    def test_ieuser_is_enabled(self, analyzer):
        metadata = analyzer._get_sam_user_metadata(SAM_HIVE)
        ieuser = metadata[1000]
        assert ieuser["account_disabled"] is False

    def test_password_doesnt_expire_flag(self, analyzer):
        metadata = analyzer._get_sam_user_metadata(SAM_HIVE)
        # Administrator has pw_doesnt_expire set
        assert metadata[500]["pw_doesnt_expire"] is True
        # CFTT (RID 1003) does NOT have pw_doesnt_expire
        assert metadata[1003]["pw_doesnt_expire"] is False

    def test_password_last_set_is_populated(self, analyzer):
        metadata = analyzer._get_sam_user_metadata(SAM_HIVE)
        admin = metadata[500]
        assert admin["password_last_set"] is not None
        assert "2016" in admin["password_last_set"]
        assert "UTC" in admin["password_last_set"]

    def test_password_expires_computed_for_expiring_accounts(self, analyzer):
        metadata = analyzer._get_sam_user_metadata(SAM_HIVE)
        # CFTT (RID 1003) has expiring password (42-day policy)
        cftt = metadata[1003]
        assert cftt["pw_doesnt_expire"] is False
        assert cftt["password_expires"] is not None
        assert "UTC" in cftt["password_expires"]

    def test_password_expires_none_for_non_expiring_accounts(self, analyzer):
        metadata = analyzer._get_sam_user_metadata(SAM_HIVE)
        # Administrator has pw_doesnt_expire set
        admin = metadata[500]
        assert admin["pw_doesnt_expire"] is True
        assert admin["password_expires"] is None

    def test_account_expires_none_when_never(self, analyzer):
        metadata = analyzer._get_sam_user_metadata(SAM_HIVE)
        # Most test accounts have no expiration
        admin = metadata[500]
        assert admin["account_expires"] is None

    def test_v_value_extracts_full_name_and_comment(self, analyzer):
        metadata = analyzer._get_sam_user_metadata(SAM_HIVE)
        # Check that full_name and comment keys exist (may be empty strings)
        admin = metadata[500]
        assert "full_name" in admin
        assert "comment" in admin

    def test_handles_nonexistent_file_gracefully(self, analyzer):
        metadata = analyzer._get_sam_user_metadata("/nonexistent/path/SAM")
        assert metadata == {}


# ---------------------------------------------------------------------------
# SAM hive processing tests (requires both SAM + SYSTEM)
# ---------------------------------------------------------------------------


class TestProcessSamHive:
    """Test _process_sam_hive with real NIST CFReDS SAM + SYSTEM hives."""

    def test_returns_accounts_with_system_hive(self, analyzer):
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        assert results["bootkey_available"] is True
        assert len(results["accounts"]) > 0

    def test_returns_empty_without_system_hive(self, analyzer):
        results = analyzer._process_sam_hive(SAM_HIVE, None)
        assert results["bootkey_available"] is False
        assert results["accounts"] == []

    def test_account_has_all_expected_fields(self, analyzer):
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        account = results["accounts"][0]
        expected_fields = [
            "rid",
            "username",
            "full_name",
            "comment",
            "nt_hash",
            "nt_hash_empty",
            "lm_hash",
            "lm_hash_empty",
            "account_disabled",
            "account_expires",
            "password_last_set",
            "password_expires",
            "pw_doesnt_expire",
            "bootkey_available",
        ]
        for field in expected_fields:
            assert field in account, f"Missing field: {field}"

    def test_administrator_account(self, analyzer):
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        admin = next(a for a in results["accounts"] if a["rid"] == 500)
        assert admin["username"] == "Administrator"
        assert admin["account_disabled"] is True
        assert admin["nt_hash"] == "fc525c9683e8fe067095ba2ddc971889"
        assert admin["nt_hash_empty"] is False
        assert admin["lm_hash_empty"] is True

    def test_guest_has_empty_nt_hash(self, analyzer):
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        guest = next(a for a in results["accounts"] if a["rid"] == 501)
        assert guest["username"] == "Guest"
        assert guest["nt_hash"] == EMPTY_NT_HASH
        assert guest["nt_hash_empty"] is True

    def test_all_accounts_have_empty_lm_hash(self, analyzer):
        """In modern Windows, LM hashes are typically empty."""
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        for account in results["accounts"]:
            assert account["lm_hash"] == EMPTY_LM_HASH
            assert account["lm_hash_empty"] is True

    def test_known_users_present(self, analyzer):
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        usernames = {a["username"] for a in results["accounts"]}
        assert "Administrator" in usernames
        assert "Guest" in usernames
        assert "IEUser" in usernames
        assert "CFTT" in usernames
        assert "Forensics" in usernames
        assert "CFReDS" in usernames

    def test_password_timestamps_populated(self, analyzer):
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        admin = next(a for a in results["accounts"] if a["rid"] == 500)
        assert admin["password_last_set"] is not None
        assert "2016" in admin["password_last_set"]

    def test_cftt_password_expires(self, analyzer):
        """CFTT account has an expiring password (42-day domain policy)."""
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        cftt = next(a for a in results["accounts"] if a["username"] == "CFTT")
        assert cftt["pw_doesnt_expire"] is False
        assert cftt["password_expires"] is not None

    def test_ieuser_password_doesnt_expire(self, analyzer):
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        ieuser = next(a for a in results["accounts"] if a["username"] == "IEUser")
        assert ieuser["pw_doesnt_expire"] is True
        assert ieuser["password_expires"] is None

    def test_bootkey_extracted(self, analyzer):
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        assert results.get("bootkey") is not None
        assert len(results["bootkey"]) > 0


# ---------------------------------------------------------------------------
# Display formatting tests
# ---------------------------------------------------------------------------


class TestFormatSamAccountsMarkdown:
    def test_basic_account_formatting(self, analyzer):
        accounts = [
            {
                "rid": 500,
                "username": "Administrator",
                "full_name": "Built-in Admin",
                "comment": "Admin account",
                "nt_hash": "fc525c9683e8fe067095ba2ddc971889",
                "nt_hash_empty": False,
                "lm_hash": EMPTY_LM_HASH,
                "lm_hash_empty": True,
                "account_disabled": True,
                "account_expires": None,
                "password_last_set": "2016-03-22 20:55:15 UTC",
                "password_expires": None,
                "pw_doesnt_expire": True,
            }
        ]
        md = analyzer._format_sam_accounts_markdown(accounts)
        assert "### RID 500: Administrator (DISABLED)" in md
        assert "**Full Name**: Built-in Admin" in md
        assert "**Comment**: Admin account" in md
        assert "**NT Hash**: `fc525c9683e8fe067095ba2ddc971889`" in md
        assert "Empty (no LM hash stored)" in md
        assert "**Account Expires**: Never" in md
        assert "**Password Last Set**: 2016-03-22 20:55:15 UTC" in md
        assert "Never (password set to not expire)" in md

    def test_enabled_account_no_disabled_tag(self, analyzer):
        accounts = [
            {
                "rid": 1000,
                "username": "TestUser",
                "full_name": "",
                "comment": "",
                "nt_hash": "abcdef1234567890abcdef1234567890",
                "nt_hash_empty": False,
                "lm_hash": EMPTY_LM_HASH,
                "lm_hash_empty": True,
                "account_disabled": False,
                "account_expires": "2025-12-31 23:59:59 UTC",
                "password_last_set": "2025-01-01 00:00:00 UTC",
                "password_expires": "2025-02-12 00:00:00 UTC",
                "pw_doesnt_expire": False,
            }
        ]
        md = analyzer._format_sam_accounts_markdown(accounts)
        assert "(DISABLED)" not in md
        assert "**Account Expires**: 2025-12-31 23:59:59 UTC" in md
        assert "**Password Expires**: 2025-02-12 00:00:00 UTC" in md

    def test_empty_nt_hash_annotated(self, analyzer):
        accounts = [
            {
                "rid": 501,
                "username": "Guest",
                "full_name": "",
                "comment": "",
                "nt_hash": EMPTY_NT_HASH,
                "nt_hash_empty": True,
                "lm_hash": EMPTY_LM_HASH,
                "lm_hash_empty": True,
                "account_disabled": True,
                "account_expires": None,
                "password_last_set": None,
                "password_expires": None,
                "pw_doesnt_expire": True,
            }
        ]
        md = analyzer._format_sam_accounts_markdown(accounts)
        assert "(empty password)" in md

    def test_limit_truncates_accounts(self, analyzer):
        accounts = [
            {
                "rid": i,
                "username": f"user{i}",
                "full_name": "",
                "comment": "",
                "nt_hash": None,
                "nt_hash_empty": True,
                "lm_hash": None,
                "lm_hash_empty": True,
                "account_disabled": False,
                "account_expires": None,
                "password_last_set": None,
                "password_expires": None,
                "pw_doesnt_expire": True,
            }
            for i in range(20)
        ]
        md = analyzer._format_sam_accounts_markdown(accounts, limit=5)
        assert "user4" in md
        assert "user5" not in md
        assert "15 more accounts" in md


class TestFormatSamAccountsText:
    def test_basic_text_formatting(self, analyzer):
        accounts = [
            {
                "rid": 500,
                "username": "Administrator",
                "full_name": "Built-in Admin",
                "comment": "Admin account",
                "nt_hash": "fc525c9683e8fe067095ba2ddc971889",
                "nt_hash_empty": False,
                "lm_hash": EMPTY_LM_HASH,
                "lm_hash_empty": True,
                "account_disabled": True,
                "account_expires": None,
                "password_last_set": "2016-03-22 20:55:15 UTC",
                "password_expires": None,
                "pw_doesnt_expire": True,
            }
        ]
        lines = analyzer._format_sam_accounts_text(accounts)
        text = "\n".join(lines)
        assert "RID 500: Administrator" in text
        assert "[DISABLED]" in text
        assert "Full Name: Built-in Admin" in text
        assert "Comment: Admin account" in text
        assert "NT Hash: fc525c9683e8fe067095ba2ddc971889" in text
        assert "LM Hash: (empty)" in text
        assert "Account Expires: Never" in text
        assert "Password Last Set: 2016-03-22 20:55:15 UTC" in text
        assert "Never (password set to not expire)" in text

    def test_empty_nt_hash_annotated(self, analyzer):
        accounts = [
            {
                "rid": 501,
                "username": "Guest",
                "full_name": "",
                "comment": "",
                "nt_hash": EMPTY_NT_HASH,
                "nt_hash_empty": True,
                "lm_hash": EMPTY_LM_HASH,
                "lm_hash_empty": True,
                "account_disabled": True,
                "account_expires": None,
                "password_last_set": None,
                "password_expires": None,
                "pw_doesnt_expire": True,
            }
        ]
        lines = analyzer._format_sam_accounts_text(accounts)
        text = "\n".join(lines)
        assert "(empty password)" in text


# ---------------------------------------------------------------------------
# Hive type identification
# ---------------------------------------------------------------------------


class TestIdentifyHiveType:
    def test_identifies_sam_hive(self, analyzer):
        assert analyzer._identify_hive_type(SAM_HIVE) == "SAM"

    def test_identifies_system_hive(self, analyzer):
        assert analyzer._identify_hive_type(SYSTEM_HIVE) == "SYSTEM"

    def test_identifies_security_hive(self, analyzer):
        assert analyzer._identify_hive_type(SECURITY_HIVE) == "SECURITY"

    def test_nonexistent_file_returns_none(self, analyzer):
        assert analyzer._identify_hive_type("/nonexistent/path") is None


# ---------------------------------------------------------------------------
# Machine SID extraction
# ---------------------------------------------------------------------------


class TestExtractMachineSid:
    def test_extracts_sid_from_sam_hive(self, analyzer):
        sid = analyzer._extract_machine_sid(SAM_HIVE)
        assert sid is not None
        assert sid.startswith("S-1-5-21-")

    def test_sid_has_four_sub_authorities(self, analyzer):
        sid = analyzer._extract_machine_sid(SAM_HIVE)
        assert sid is not None
        parts = sid.split("-")
        # S-1-5-21-X-Y-Z => 7 parts
        assert len(parts) == 7

    def test_sid_sub_authorities_are_numeric(self, analyzer):
        sid = analyzer._extract_machine_sid(SAM_HIVE)
        assert sid is not None
        parts = sid.split("-")
        for part in parts[3:]:  # sub-authorities after S-1-5
            assert part.isdigit()

    def test_nonexistent_file_returns_none(self, analyzer):
        sid = analyzer._extract_machine_sid("/nonexistent/path")
        assert sid is None

    def test_process_sam_hive_includes_sid(self, analyzer):
        results = analyzer._process_sam_hive(SAM_HIVE, SYSTEM_HIVE)
        assert "machine_sid" in results
        assert results["machine_sid"].startswith("S-1-5-21-")

    def test_exact_sid_value_from_nist_hive(self, analyzer):
        """Pin the exact SID extracted from the NIST CFReDS SAM hive."""
        sid = analyzer._extract_machine_sid(SAM_HIVE)
        assert sid == "S-1-5-21-4144202625-3024446806-325092953"

    def test_v_value_too_short_returns_none(self, analyzer):
        """V value shorter than 48 bytes (4 descriptors × 12 bytes) should return None."""
        short_v = b"\x00" * 44
        with patch("file_enrichment_modules.registry_hive.analyzer.RegistryHive") as mock_hive_cls:
            mock_key = MagicMock()
            mock_key.get_value.return_value = short_v
            mock_hive_cls.return_value.get_key.return_value = mock_key
            sid = analyzer._extract_machine_sid("/fake/sam")
            assert sid is None

    def test_v_value_not_bytes_returns_none(self, analyzer):
        """V value that isn't bytes should return None."""
        with patch("file_enrichment_modules.registry_hive.analyzer.RegistryHive") as mock_hive_cls:
            mock_key = MagicMock()
            mock_key.get_value.return_value = 12345  # not bytes
            mock_hive_cls.return_value.get_key.return_value = mock_key
            sid = analyzer._extract_machine_sid("/fake/sam")
            assert sid is None

    def test_negative_sid_offset_returns_none(self, analyzer):
        """SID descriptor with a negative Offset (LONG) should return None."""
        entries = [
            struct.pack("<iII", 0, 10, 0),  # entry 0: security descriptor
            struct.pack("<iII", -1, 28, 0),  # entry 1: SID — negative offset
            struct.pack("<iII", 10, 5, 0),  # entry 2: OEM info
            struct.pack("<iII", 15, 5, 0),  # entry 3: replica
        ]
        data_region = b"\x00" * 30
        v_data = b"".join(entries) + data_region
        with patch("file_enrichment_modules.registry_hive.analyzer.RegistryHive") as mock_hive_cls:
            mock_key = MagicMock()
            mock_key.get_value.return_value = v_data
            mock_hive_cls.return_value.get_key.return_value = mock_key
            sid = analyzer._extract_machine_sid("/fake/sam")
            assert sid is None

    def test_zero_sub_authority_count_returns_none(self, analyzer):
        """SID binary with SubAuthorityCount = 0 should return None."""
        # A SID with 0 sub-authorities is technically 8 bytes but not a valid machine SID.
        sid_binary = (
            bytes(
                [
                    0x01,  # Revision = 1
                    0x00,  # SubAuthorityCount = 0
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x05,  # Authority = 5
                ]
            )
            + b"\x00" * 8
        )  # padding to reach sid_length >= 12

        entries = [
            struct.pack("<III", 0, 10, 0),
            struct.pack("<III", 10, len(sid_binary), 0),
            struct.pack("<III", 10 + len(sid_binary), 5, 0),
            struct.pack("<III", 15 + len(sid_binary), 5, 0),
        ]
        data_region = b"\x00" * 10 + sid_binary + b"\x00" * 10
        v_data = b"".join(entries) + data_region
        with patch("file_enrichment_modules.registry_hive.analyzer.RegistryHive") as mock_hive_cls:
            mock_key = MagicMock()
            mock_key.get_value.return_value = v_data
            mock_hive_cls.return_value.get_key.return_value = mock_key
            sid = analyzer._extract_machine_sid("/fake/sam")
            assert sid is None

    def test_sid_descriptor_length_too_short_returns_none(self, analyzer):
        """SID descriptor with length < 12 should return None (too small for a valid SID)."""
        # 4 entries (domain object), entry 1 (SID) has length = 4 (too short)
        entries = [
            struct.pack("<III", 0, 10, 0),  # entry 0: security descriptor
            struct.pack("<III", 10, 4, 0),  # entry 1: SID — length only 4
            struct.pack("<III", 14, 5, 0),  # entry 2: OEM info
            struct.pack("<III", 19, 5, 0),  # entry 3: replica
        ]
        data_region = b"\x00" * 30
        v_data = b"".join(entries) + data_region
        with patch("file_enrichment_modules.registry_hive.analyzer.RegistryHive") as mock_hive_cls:
            mock_key = MagicMock()
            mock_key.get_value.return_value = v_data
            mock_hive_cls.return_value.get_key.return_value = mock_key
            sid = analyzer._extract_machine_sid("/fake/sam")
            assert sid is None

    def test_sid_descriptor_points_past_end_returns_none(self, analyzer):
        """SID descriptor pointing beyond the V value should return None."""
        entries = [
            struct.pack("<III", 0, 10, 0),
            struct.pack("<III", 10, 28, 0),  # SID: offset 10, length 28
            struct.pack("<III", 38, 5, 0),
            struct.pack("<III", 43, 5, 0),
        ]
        # Data region is only 20 bytes — too small for entry 1's offset+length
        data_region = b"\x00" * 20
        v_data = b"".join(entries) + data_region
        with patch("file_enrichment_modules.registry_hive.analyzer.RegistryHive") as mock_hive_cls:
            mock_key = MagicMock()
            mock_key.get_value.return_value = v_data
            mock_hive_cls.return_value.get_key.return_value = mock_key
            sid = analyzer._extract_machine_sid("/fake/sam")
            assert sid is None

    def test_sid_binary_bad_sub_authority_count_returns_none(self, analyzer):
        """SID binary with SubAuthorityCount claiming more data than available should return None."""
        # Build a valid-looking V structure with 4 entries, but the SID binary
        # has SubAuthorityCount = 10 which would need 48 bytes but only 16 available
        sid_binary = bytes(
            [
                0x01,  # Revision
                0x0A,  # SubAuthorityCount = 10 (needs 8 + 40 = 48 bytes)
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x05,  # Authority = 5
                # Only 8 bytes of sub-authorities follow (enough for 2, not 10)
            ]
        ) + struct.pack("<II", 21, 1234567890)

        entries = [
            struct.pack("<III", 0, 10, 0),
            struct.pack("<III", 10, len(sid_binary), 0),
            struct.pack("<III", 10 + len(sid_binary), 5, 0),
            struct.pack("<III", 15 + len(sid_binary), 5, 0),
        ]
        data_region = b"\x00" * 10 + sid_binary + b"\x00" * 10
        v_data = b"".join(entries) + data_region
        with patch("file_enrichment_modules.registry_hive.analyzer.RegistryHive") as mock_hive_cls:
            mock_key = MagicMock()
            mock_key.get_value.return_value = v_data
            mock_hive_cls.return_value.get_key.return_value = mock_key
            sid = analyzer._extract_machine_sid("/fake/sam")
            assert sid is None

    def test_synthetic_valid_sid_round_trips(self, analyzer):
        """Build a synthetic V value with a known SID and verify it parses correctly."""
        # Build SID binary for S-1-5-21-1000-2000-3000
        sid_binary = bytes(
            [
                0x01,  # Revision = 1
                0x04,  # SubAuthorityCount = 4
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x05,  # Authority = 5 (big-endian)
            ]
        ) + struct.pack("<IIII", 21, 1000, 2000, 3000)  # 4 sub-authorities (LE)

        sd_data = b"\x01" * 20  # fake security descriptor
        oem_data = b"\x02" * 8  # fake OEM info
        replica_data = b"\x03" * 4  # fake replica

        sd_off = 0
        sid_off = sd_off + len(sd_data)
        oem_off = sid_off + len(sid_binary)
        rep_off = oem_off + len(oem_data)

        entries = [
            struct.pack("<III", sd_off, len(sd_data), 0),
            struct.pack("<III", sid_off, len(sid_binary), 0),
            struct.pack("<III", oem_off, len(oem_data), 0),
            struct.pack("<III", rep_off, len(replica_data), 0),
        ]
        data_region = sd_data + sid_binary + oem_data + replica_data
        v_data = b"".join(entries) + data_region

        with patch("file_enrichment_modules.registry_hive.analyzer.RegistryHive") as mock_hive_cls:
            mock_key = MagicMock()
            mock_key.get_value.return_value = v_data
            mock_hive_cls.return_value.get_key.return_value = mock_key
            sid = analyzer._extract_machine_sid("/fake/sam")
            assert sid == "S-1-5-21-1000-2000-3000"


# ---------------------------------------------------------------------------
# LSA secrets formatting (text)
# ---------------------------------------------------------------------------


class TestFormatLsaSecretsText:
    def test_dcc_entries_formatted(self, analyzer):
        secrets = [
            {
                "name": "dcc",
                "secret_type": "dcc",
                "decrypted": True,
                "value": "2 cached domain credential(s)",
                "entries": [
                    {
                        "domain": "CORP.LOCAL",
                        "username": "admin",
                        "hash_value": "aabbccdd",
                        "iteration": 10240,
                        "lastwrite": "2025-01-01 12:00:00",
                    },
                    {
                        "domain": "CORP.LOCAL",
                        "username": "jdoe",
                        "hash_value": "11223344",
                        "iteration": 10240,
                        "lastwrite": "2025-01-02 12:00:00",
                    },
                ],
                "bootkey_available": True,
            }
        ]
        lines = analyzer._format_lsa_secrets_text(secrets)
        text = "\n".join(lines)
        assert "Cached Domain Credentials (DCC2): 2 account(s)" in text
        assert "CORP.LOCAL\\admin" in text
        assert "$DCC2$10240#admin#aabbccdd" in text
        assert "Last Write: 2025-01-01 12:00:00" in text
        assert "CORP.LOCAL\\jdoe" in text

    def test_dpapi_system_formatted(self, analyzer):
        secrets = [
            {
                "name": "DPAPI_SYSTEM",
                "secret_type": "dpapi_system",
                "decrypted": True,
                "value": "{'machine_key': 'aabb', 'user_key': 'ccdd'}",
                "machine_key": "aabb",
                "user_key": "ccdd",
                "bootkey_available": True,
            }
        ]
        lines = analyzer._format_lsa_secrets_text(secrets)
        text = "\n".join(lines)
        assert "DPAPI_SYSTEM:" in text
        assert "Machine Key: aabb" in text
        assert "User Key: ccdd" in text

    def test_hex_blob_truncated(self, analyzer):
        long_hex = "ab" * 100  # 200 hex chars = 100 bytes
        secrets = [
            {
                "name": "NK$LM",
                "secret_type": "hex_blob",
                "decrypted": True,
                "value": long_hex,
                "bootkey_available": True,
            }
        ]
        lines = analyzer._format_lsa_secrets_text(secrets)
        text = "\n".join(lines)
        assert "NK$LM:" in text
        assert "..." in text
        assert "(100 bytes)" in text

    def test_hex_blob_short_not_truncated(self, analyzer):
        short_hex = "abcdef1234"
        secrets = [
            {
                "name": "lsa_key",
                "secret_type": "hex_blob",
                "decrypted": True,
                "value": short_hex,
                "bootkey_available": True,
            }
        ]
        lines = analyzer._format_lsa_secrets_text(secrets)
        text = "\n".join(lines)
        assert "lsa_key:" in text
        assert "abcdef1234" in text
        assert "..." not in text

    def test_generic_secret_formatted(self, analyzer):
        secrets = [
            {
                "name": "some_secret",
                "secret_type": "generic",
                "decrypted": True,
                "value": "secret_value_here",
                "bootkey_available": True,
            }
        ]
        lines = analyzer._format_lsa_secrets_text(secrets)
        text = "\n".join(lines)
        assert "some_secret: secret_value_here" in text

    def test_encrypted_secret(self, analyzer):
        secrets = [
            {
                "name": "locked",
                "secret_type": "generic",
                "decrypted": False,
                "value": "",
                "bootkey_available": False,
            }
        ]
        lines = analyzer._format_lsa_secrets_text(secrets)
        text = "\n".join(lines)
        assert "locked: (encrypted)" in text

    def test_dcc_without_iteration_no_dcc2_format(self, analyzer):
        secrets = [
            {
                "name": "dcc",
                "secret_type": "dcc",
                "decrypted": True,
                "value": "1 cached domain credential(s)",
                "entries": [
                    {
                        "domain": "DOMAIN",
                        "username": "user",
                        "hash_value": "deadbeef",
                        "iteration": 0,
                        "lastwrite": "",
                    },
                ],
                "bootkey_available": True,
            }
        ]
        lines = analyzer._format_lsa_secrets_text(secrets)
        text = "\n".join(lines)
        assert "Hash: deadbeef" in text
        assert "$DCC2$" not in text


# ---------------------------------------------------------------------------
# LSA secrets formatting (markdown)
# ---------------------------------------------------------------------------


class TestFormatLsaSecretsMarkdown:
    def test_dcc_entries_formatted(self, analyzer):
        secrets = [
            {
                "name": "dcc",
                "secret_type": "dcc",
                "decrypted": True,
                "value": "1 cached domain credential(s)",
                "entries": [
                    {
                        "domain": "CORP.LOCAL",
                        "username": "admin",
                        "hash_value": "aabbccdd",
                        "iteration": 10240,
                        "lastwrite": "2025-06-15 08:30:00",
                    },
                ],
                "bootkey_available": True,
            }
        ]
        md = analyzer._format_lsa_secrets_markdown(secrets)
        assert "### Cached Domain Credentials (DCC2)" in md
        assert "**1** cached account(s)" in md
        assert "CORP.LOCAL" in md
        assert "`$DCC2$10240#admin#aabbccdd`" in md
        assert "Last Write: 2025-06-15 08:30:00" in md

    def test_dpapi_system_formatted(self, analyzer):
        secrets = [
            {
                "name": "DPAPI_SYSTEM",
                "secret_type": "dpapi_system",
                "decrypted": True,
                "value": "{'machine_key': 'aabb', 'user_key': 'ccdd'}",
                "machine_key": "aabb",
                "user_key": "ccdd",
                "bootkey_available": True,
            }
        ]
        md = analyzer._format_lsa_secrets_markdown(secrets)
        assert "### DPAPI_SYSTEM" in md
        assert "**Machine Key**: `aabb`" in md
        assert "**User Key**: `ccdd`" in md

    def test_hex_blob_truncated(self, analyzer):
        long_hex = "ab" * 100
        secrets = [
            {
                "name": "NK$LM",
                "secret_type": "hex_blob",
                "decrypted": True,
                "value": long_hex,
                "bootkey_available": True,
            }
        ]
        md = analyzer._format_lsa_secrets_markdown(secrets)
        assert "### NK$LM" in md
        assert "(100 bytes)" in md

    def test_generic_encrypted_secret(self, analyzer):
        secrets = [
            {
                "name": "locked",
                "secret_type": "generic",
                "decrypted": False,
                "value": "",
                "bootkey_available": False,
            }
        ]
        md = analyzer._format_lsa_secrets_markdown(secrets)
        assert "*(encrypted)*" in md

    def test_limit_respected(self, analyzer):
        secrets = [
            {
                "name": f"secret_{i}",
                "secret_type": "generic",
                "decrypted": True,
                "value": f"val_{i}",
                "bootkey_available": True,
            }
            for i in range(15)
        ]
        md = analyzer._format_lsa_secrets_markdown(secrets, limit=5)
        assert "secret_4" in md
        assert "secret_5" not in md
        assert "10 more secrets" in md
