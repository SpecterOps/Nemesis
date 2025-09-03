from collections.abc import Callable
from pathlib import Path

import pytest


def _get_file_path(name: str) -> Path:
    return Path(__file__).parent / "fixtures" / name


def _read_file_text(name: str) -> str:
    return _get_file_path(name).read_text()


def _read_file_bytes(name: str) -> bytes:
    return _get_file_path(name).read_bytes()


@pytest.fixture
def read_file_text() -> Callable[[str], str]:
    return _read_file_text


@pytest.fixture
def read_file_bytes() -> Callable[[str], bytes]:
    return _read_file_bytes


@pytest.fixture
def get_file_path() -> Callable[[str], Path]:
    return _get_file_path


@pytest.fixture
def blob_without_entropy() -> bytes:
    return _read_file_bytes("blob_without_entropy.bin")


@pytest.fixture
def blob_with_entropy() -> bytes:
    return _read_file_bytes("blob_with_entropy.bin")
