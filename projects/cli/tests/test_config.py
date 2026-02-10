"""Tests for cli.config module - StrictHttpUrl, credential models, and config validation."""

import tempfile
from pathlib import Path

import pytest
import yaml
from cli.config import (
    CobaltStrikeConfig,
    Config,
    MythicConfig,
    NemesisConfig,
    OutflankConfig,
    PasswordCredential,
    StrictHttpUrl,
    TokenCredential,
    load_config,
)
from pydantic import ValidationError

# --- StrictHttpUrl ---


class TestStrictHttpUrl:
    def test_valid_https_url(self):
        url = StrictHttpUrl("https://example.com")
        assert str(url) == "https://example.com"

    def test_valid_http_url(self):
        url = StrictHttpUrl("http://example.com")
        assert str(url) == "http://example.com"

    def test_valid_url_with_port(self):
        url = StrictHttpUrl("https://example.com:8443")
        assert str(url) == "https://example.com:8443"

    def test_strips_trailing_slash(self):
        url = StrictHttpUrl("https://example.com/")
        assert str(url) == "https://example.com"

    def test_strips_multiple_trailing_slashes(self):
        url = StrictHttpUrl("https://example.com///")
        assert str(url) == "https://example.com"

    def test_repr(self):
        url = StrictHttpUrl("https://example.com/")
        assert repr(url) == "StrictHttpUrl('https://example.com')"

    def test_is_string_subclass(self):
        url = StrictHttpUrl("https://example.com")
        assert isinstance(url, str)

    def test_url_with_path(self):
        url = StrictHttpUrl("https://example.com/api/v1")
        assert str(url) == "https://example.com/api/v1"


# --- Credential Models ---


class TestPasswordCredential:
    def test_create(self):
        cred = PasswordCredential(username="admin", password="secret")
        assert cred.username == "admin"
        assert cred.password == "secret"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            PasswordCredential(username="admin", password="secret", extra="nope")


class TestTokenCredential:
    def test_create(self):
        cred = TokenCredential(token="abc123")
        assert cred.token == "abc123"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            TokenCredential(token="abc123", extra="nope")


# --- NemesisConfig ---


class TestNemesisConfig:
    def test_create_with_defaults(self):
        cfg = NemesisConfig(
            url=StrictHttpUrl("https://nemesis.local:8080"),
            credential=PasswordCredential(username="u", password="p"),
        )
        assert str(cfg.url) == "https://nemesis.local:8080"
        assert cfg.expiration_days == 100
        assert cfg.max_file_size == 1_000_000_000

    def test_create_with_custom_values(self):
        cfg = NemesisConfig(
            url=StrictHttpUrl("https://nemesis.local:8080"),
            credential=PasswordCredential(username="u", password="p"),
            expiration_days=30,
            max_file_size=500_000,
        )
        assert cfg.expiration_days == 30
        assert cfg.max_file_size == 500_000

    def test_expiration_days_must_be_positive(self):
        with pytest.raises(ValidationError):
            NemesisConfig(
                url=StrictHttpUrl("https://nemesis.local"),
                credential=PasswordCredential(username="u", password="p"),
                expiration_days=0,
            )

    def test_max_file_size_must_be_positive(self):
        with pytest.raises(ValidationError):
            NemesisConfig(
                url=StrictHttpUrl("https://nemesis.local"),
                credential=PasswordCredential(username="u", password="p"),
                max_file_size=-1,
            )


# --- MythicConfig ---


class TestMythicConfig:
    def test_create_with_password_credential(self):
        cfg = MythicConfig(
            url=StrictHttpUrl("https://mythic.local:7443"),
            credential=PasswordCredential(username="mythic_admin", password="pass"),
        )
        assert isinstance(cfg.credential, PasswordCredential)

    def test_create_with_token_credential(self):
        cfg = MythicConfig(
            url=StrictHttpUrl("https://mythic.local:7443"),
            credential=TokenCredential(token="my-api-token"),
        )
        assert isinstance(cfg.credential, TokenCredential)

    def test_validate_credential_from_dict_token(self):
        """Test that the field_validator correctly handles dict input with token."""
        cfg = MythicConfig(
            url=StrictHttpUrl("https://mythic.local:7443"),
            credential={"token": "my-api-token"},
        )
        assert isinstance(cfg.credential, TokenCredential)
        assert cfg.credential.token == "my-api-token"

    def test_validate_credential_from_dict_password(self):
        """Test that the field_validator correctly handles dict input with username/password."""
        cfg = MythicConfig(
            url=StrictHttpUrl("https://mythic.local:7443"),
            credential={"username": "admin", "password": "secret"},
        )
        assert isinstance(cfg.credential, PasswordCredential)
        assert cfg.credential.username == "admin"


# --- OutflankConfig ---


class TestOutflankConfig:
    def test_create_minimal(self):
        cfg = OutflankConfig(
            url=StrictHttpUrl("https://outflank.local"),
            credential=PasswordCredential(username="u", password="p"),
        )
        assert cfg.downloads_dir_path is None
        assert cfg.poll_interval_sec == 3

    def test_create_with_downloads_dir(self):
        cfg = OutflankConfig(
            url=StrictHttpUrl("https://outflank.local"),
            credential=PasswordCredential(username="u", password="p"),
            downloads_dir_path="/tmp/downloads",
        )
        assert cfg.downloads_dir_path == Path("/tmp/downloads")

    def test_poll_interval_must_be_positive(self):
        with pytest.raises(ValidationError):
            OutflankConfig(
                url=StrictHttpUrl("https://outflank.local"),
                credential=PasswordCredential(username="u", password="p"),
                poll_interval_sec=0,
            )


# --- CobaltStrikeConfig ---


class TestCobaltStrikeConfig:
    def test_create(self):
        cfg = CobaltStrikeConfig(
            url=StrictHttpUrl("https://cs.local"),
            credential=PasswordCredential(username="u", password="p"),
            project="assessment-1",
        )
        assert cfg.project == "assessment-1"
        assert cfg.poll_interval_sec == 3

    def test_poll_interval_must_be_positive(self):
        with pytest.raises(ValidationError):
            CobaltStrikeConfig(
                url=StrictHttpUrl("https://cs.local"),
                credential=PasswordCredential(username="u", password="p"),
                project="test",
                poll_interval_sec=-1,
            )


# --- Config (root) ---


class TestConfig:
    def _nemesis_cfg(self):
        return {
            "url": "https://nemesis.local:8080",
            "credential": {"username": "u", "password": "p"},
        }

    def test_create_minimal(self):
        cfg = Config(nemesis=self._nemesis_cfg())
        assert cfg.nemesis is not None
        assert cfg.mythic == []
        assert cfg.outflank == []
        assert cfg.cobaltstrike == []

    def test_ensure_list_wraps_dict(self):
        """ensure_list validator should wrap a single dict in a list."""
        cfg = Config(
            nemesis=self._nemesis_cfg(),
            mythic={
                "url": "https://mythic.local:7443",
                "credential": {"username": "u", "password": "p"},
            },
        )
        assert isinstance(cfg.mythic, list)
        assert len(cfg.mythic) == 1

    def test_ensure_list_none_becomes_empty(self):
        cfg = Config(nemesis=self._nemesis_cfg(), mythic=None)
        assert cfg.mythic == []

    def test_cache_db_path_default(self):
        cfg = Config(nemesis=self._nemesis_cfg())
        assert cfg.cache_db_path == Path("/tmp/connectors")

    def test_cache_db_path_custom(self):
        cfg = Config(nemesis=self._nemesis_cfg(), cache_db_path="/custom/path")
        assert cfg.cache_db_path == Path("/custom/path")

    def test_conn_timeout_default(self):
        cfg = Config(nemesis=self._nemesis_cfg())
        assert cfg.conn_timeout_sec == 30


# --- load_config ---


class TestLoadConfig:
    def test_load_valid_yaml(self):
        config_data = {
            "nemesis": {
                "url": "https://nemesis.local:8080",
                "credential": {"username": "admin", "password": "pass"},
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            f.flush()
            cfg = load_config(f.name)

        assert isinstance(cfg, Config)
        assert str(cfg.nemesis.url) == "https://nemesis.local:8080"

    def test_load_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/config.yaml")


# --- Settings file integration tests ---
# Validate that the example settings YAML files parse correctly through the Config model.

SETTINGS_DIR = Path(__file__).resolve().parent.parent


class TestSettingsCobaltstrike:
    """Validate settings_cobaltstrike.yaml parses correctly through the Config model."""

    @pytest.fixture()
    def cfg(self):
        return load_config(str(SETTINGS_DIR / "settings_cobaltstrike.yaml"))

    def test_loads_as_config(self, cfg):
        assert isinstance(cfg, Config)

    def test_root_fields(self, cfg):
        assert cfg.cache_db_path == Path("/tmp/nemesis_connectors")
        assert cfg.conn_timeout_sec == 5
        assert cfg.validate_https_certs is False

    def test_nemesis_section(self, cfg):
        assert str(cfg.nemesis.url) == "https://nemesis.example.com"
        assert cfg.nemesis.credential.username == "connector_bot"
        assert cfg.nemesis.credential.password == "pass"
        assert cfg.nemesis.expiration_days == 100
        assert cfg.nemesis.max_file_size == 1_000_000_000

    def test_cobaltstrike_section(self, cfg):
        assert isinstance(cfg.cobaltstrike, list)
        assert len(cfg.cobaltstrike) == 1
        cs = cfg.cobaltstrike[0]
        assert str(cs.url) == "https://cobaltstrike.example.com:50443"
        assert cs.credential.username == "nemesis_bot"
        assert cs.credential.password == "cobaltstrike_password"
        assert cs.project == "my-assessment"
        assert cs.poll_interval_sec == 3

    def test_unset_connectors_are_empty(self, cfg):
        assert cfg.mythic == []
        assert cfg.outflank == []


class TestSettingsOutflank:
    """Validate settings_outflank.yaml parses correctly through the Config model."""

    @pytest.fixture()
    def cfg(self):
        return load_config(str(SETTINGS_DIR / "settings_outflank.yaml"))

    def test_loads_as_config(self, cfg):
        assert isinstance(cfg, Config)

    def test_root_fields(self, cfg):
        assert cfg.cache_db_path == Path("/tmp/nemesis_connectors")
        assert cfg.conn_timeout_sec == 5
        assert cfg.validate_https_certs is True

    def test_nemesis_section(self, cfg):
        assert str(cfg.nemesis.url) == "https://nemesis.example.com"
        assert cfg.nemesis.credential.username == "connector_bot"

    def test_outflank_section(self, cfg):
        assert isinstance(cfg.outflank, list)
        assert len(cfg.outflank) == 1
        of = cfg.outflank[0]
        assert str(of.url) == "https://stage1.example.com"
        assert of.credential.username == "nemesis_bot"
        assert of.credential.password == "outflank_password"
        assert of.downloads_dir_path is None
        assert of.poll_interval_sec == 3  # default

    def test_unset_connectors_are_empty(self, cfg):
        assert cfg.mythic == []
        assert cfg.cobaltstrike == []
