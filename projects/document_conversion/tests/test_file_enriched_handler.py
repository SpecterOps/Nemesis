"""file_enriched handler: the encryption check only downloads files that could be protected PDFs or Office documents,
shares one S3 client, and runs off the event loop; a missing object is dropped."""

import sys
import threading
import types
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from minio.error import S3Error

# document_conversion.workflow imports activities that reach Dapr/SeaweedFS at import time
_fake_workflow = types.ModuleType("document_conversion.workflow")
_fake_workflow.document_conversion_workflow = MagicMock(name="document_conversion_workflow")  # pyright: ignore[reportAttributeAccessIssue]
sys.modules.setdefault("document_conversion.workflow", _fake_workflow)

import document_conversion.subscriptions.file_enriched as handler  # noqa: E402
import document_conversion.workflow_manager as wm  # noqa: E402


def _file(magic_type: str):
    return SimpleNamespace(object_id=uuid4(), magic_type=magic_type, path="/x/file")


class _Storage:
    """Records downloads; `missing` makes them fail like Minio does for an absent object."""

    def __init__(self, missing: bool = False):
        self.missing = missing
        self.downloads = []

    @contextmanager
    def _temp(self):
        yield SimpleNamespace(name="/tmp/downloaded")

    def download(self, object_id):
        self.downloads.append(object_id)
        if self.missing:
            raise S3Error(code="NoSuchKey", message="gone", resource="r", request_id="", host_id="", response=None)  # pyright: ignore[reportArgumentType]
        return self._temp()


@pytest.fixture
def storage(monkeypatch):
    s = _Storage()
    monkeypatch.setattr(handler, "_storage", lambda: s)
    return s


@pytest.mark.parametrize("magic", ["Composite Document File V2 Document, Security: 1", "CDFV2 Encrypted"])
def test_encrypted_magic_needs_no_download(storage, magic):
    assert handler.is_encrypted_file(_file(magic)) is True
    assert storage.downloads == []


@pytest.mark.parametrize(
    "magic",
    [
        "ELF 64-bit LSB pie executable, x86-64",
        "data",
        "MS Windows registry file, NT/2000 or above",
        "7-zip archive data",
    ],
)
def test_files_that_cannot_be_protected_are_not_downloaded(storage, magic):
    assert handler.is_encrypted_file(_file(magic)) is False
    assert storage.downloads == []


def test_pdf_is_downloaded_and_checked(storage, monkeypatch):
    monkeypatch.setattr(handler, "is_pdf_encrypted", lambda path: True)
    f = _file("PDF document, version 1.7")
    assert handler.is_encrypted_file(f) is True
    assert storage.downloads == [f.object_id]


@pytest.mark.parametrize("magic", ["Microsoft Word 2007+", "Zip archive data, at least v2.0 to extract", ""])
def test_office_zip_and_unknown_types_are_checked(storage, monkeypatch, magic):
    checked = []
    monkeypatch.setattr(handler, "check_office_encryption", lambda path: checked.append("office") or False)
    monkeypatch.setattr(handler, "check_rms_protected", lambda path: checked.append("rms") or True)
    assert handler.is_encrypted_file(_file(magic)) is True
    assert checked == ["office", "rms"]
    assert len(storage.downloads) == 1


def test_missing_object_raises_no_such_key(monkeypatch):
    monkeypatch.setattr(handler, "_storage", lambda: _Storage(missing=True))
    with pytest.raises(S3Error) as e:
        handler.is_encrypted_file(_file("PDF document"))
    assert e.value.code == "NoSuchKey"


def test_one_s3_client_per_process():
    handler._storage.cache_clear()
    try:
        with patch.object(handler, "StorageS3") as storage_cls:
            assert handler._storage() is handler._storage()
        storage_cls.assert_called_once_with()
    finally:
        handler._storage.cache_clear()


# --- the handler ---


@pytest.fixture
def start(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr(wm, "start_workflow_with_concurrency_control", mock)
    return mock


@pytest.mark.asyncio
async def test_handler_checks_off_the_event_loop_and_starts_the_workflow(monkeypatch, start):
    seen = []
    monkeypatch.setattr(handler, "is_encrypted_file", lambda f: seen.append(threading.current_thread()) or False)
    f = _file("ELF 64-bit")
    await handler.file_enriched_subscription_handler(SimpleNamespace(data=f))  # pyright: ignore[reportArgumentType]
    assert seen and seen[0] is not threading.main_thread()
    start.assert_awaited_once_with(f)


@pytest.mark.asyncio
async def test_handler_skips_encrypted_files(monkeypatch, start):
    monkeypatch.setattr(handler, "is_encrypted_file", lambda f: True)
    await handler.file_enriched_subscription_handler(SimpleNamespace(data=_file("CDFV2 Encrypted")))  # pyright: ignore[reportArgumentType]
    start.assert_not_awaited()


@pytest.mark.asyncio
async def test_handler_drops_missing_objects(monkeypatch, start):
    monkeypatch.setattr(handler, "_storage", lambda: _Storage(missing=True))
    # returns normally (ack) instead of raising, so the message isn't redelivered forever
    await handler.file_enriched_subscription_handler(SimpleNamespace(data=_file("PDF document")))  # pyright: ignore[reportArgumentType]
    start.assert_not_awaited()
