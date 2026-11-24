"""Tika 4 JSON config handling (no JVM needed)."""

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

with patch("common.storage.StorageS3", MagicMock()):
    from document_conversion.activities import extract_text

REPO = Path(__file__).resolve().parents[3]
CONFIGS = ["tika-config.json", "tika-config-tesseract.json"]


def _strip_comments(text: str) -> str:
    return re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, "eng"),
        ("", "eng"),
        ("eng", "eng"),
        ("eng chi_sim chi-tra jpn", "eng+chi_sim+chi_tra+jpn"),
        ("eng+deu", "eng+deu"),
        ("  eng   spa ", "eng+spa"),
        ("script/Latin", "script/Latin"),
    ],
)
def test_ocr_languages_from_env(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("TIKA_OCR_LANGUAGES", raising=False)
    else:
        monkeypatch.setenv("TIKA_OCR_LANGUAGES", raw)
    assert extract_text.ocr_languages_from_env() == expected


@pytest.mark.parametrize("raw", ['eng", "skipOcr": true, "x": "', "eng;rm", "eng\\"])
def test_ocr_languages_reject_json_breaking_values(monkeypatch, raw):
    monkeypatch.setenv("TIKA_OCR_LANGUAGES", raw)
    with pytest.raises(ValueError, match="invalid language"):
        extract_text.ocr_languages_from_env()


def test_render_sets_the_ocr_language():
    text = (REPO / "infra/tika/tika-config-tesseract.json").read_text()
    rendered = json.loads(_strip_comments(extract_text.render_tika_config(text, "eng+deu")))
    assert rendered["text-recognizers"][0]["tesseract-ocr-parser"]["language"] == "eng+deu"


def test_render_leaves_the_no_ocr_config_alone():
    text = (REPO / "infra/tika/tika-config.json").read_text()
    assert extract_text.render_tika_config(text, "eng+deu") == text


@pytest.mark.parametrize("name", CONFIGS)
def test_configs_are_valid_tika4_json(name):
    config = json.loads(_strip_comments((REPO / "infra/tika" / name).read_text()))
    parsers = [next(iter(p)) for p in config["parsers"]]
    # Tika 4.2 refuses OCR engines under "parsers"
    assert "tesseract-ocr-parser" not in parsers
    pdf = next(p["pdf-parser"] for p in config["parsers"] if "pdf-parser" in p)
    assert pdf["pages"]["text"] in {"extract", "auto", "ocr", "extract_and_ocr", "none"}


def test_default_config_has_ocr_off_and_tesseract_config_has_it_on():
    plain = json.loads(_strip_comments((REPO / "infra/tika/tika-config.json").read_text()))
    ocr = json.loads(_strip_comments((REPO / "infra/tika/tika-config-tesseract.json").read_text()))
    assert plain["text-recognizers"] == []
    assert "tesseract-ocr-parser" in ocr["text-recognizers"][0]


@pytest.mark.parametrize("name", CONFIGS)
def test_helm_copy_matches_compose(name):
    assert (REPO / "k8s/helm/nemesis/files" / name).read_text() == (REPO / "infra/tika" / name).read_text()


def test_init_tika_loads_the_configured_file(tmp_path, monkeypatch):
    config = tmp_path / "tika.json"
    config.write_text((REPO / "infra/tika/tika-config-tesseract.json").read_text())
    monkeypatch.setenv("TIKA_CONFIG", str(config))
    monkeypatch.setenv("TIKA_OCR_LANGUAGES", "eng spa")
    seen = {}

    def fake_load(path):
        seen["config"] = Path(str(path)).read_text()
        seen["path"] = str(path)
        return MagicMock()

    fake_java = MagicMock()
    fake_java.TikaLoader.load.side_effect = fake_load
    fake_java.Paths.get.side_effect = lambda p: p
    monkeypatch.setattr(extract_text, "java", fake_java)
    monkeypatch.setattr(extract_text, "init_jvm", lambda: None)

    extract_text.init_tika()
    assert '"language": "eng+spa"' in seen["config"]
    assert not Path(seen["path"]).exists()  # temp copy removed
    assert extract_text.tika_instance is fake_java.Tika.return_value


def test_init_tika_fails_on_a_missing_config(tmp_path, monkeypatch):
    monkeypatch.setenv("TIKA_CONFIG", str(tmp_path / "missing.json"))
    monkeypatch.setattr(extract_text, "init_jvm", lambda: None)
    with pytest.raises(FileNotFoundError):
        extract_text.init_tika()
