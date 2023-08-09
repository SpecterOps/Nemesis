# Standard Libraries
from functools import cache
from unittest.mock import MagicMock, mock_open

# 3rd Party Libraries
import pytest
from pytest_mock import MockerFixture


@pytest.fixture(autouse=True)
def change_test_dir(request, monkeypatch):
    monkeypatch.chdir(request.fspath.dirname)


# Source: https://stackoverflow.com/questions/1289894/how-do-i-mock-an-open-used-in-a-with-statement-using-the-mock-framework-in-pyth
class FileMock(MagicMock):
    def __init__(self, mocker: MagicMock, **kwargs):
        super().__init__(**kwargs)

        if mocker:
            self.__dict__ = mocker.__dict__
            # configure mock object to replace the use of open(...)
            # note: this is useful in scenarios where data is written out
            _ = mock_open(mock=self)

    @property
    def read_data(self):
        return self.side_effect

    @read_data.setter
    def read_data(self, mock_data: str):
        """set mock data to be returned when `open(...).read()` is called."""
        self.side_effect = mock_open(read_data=mock_data)

    @property
    @cache
    def write_calls(self):
        """a list of calls made to `open().write(...)`"""
        handle = self.return_value
        write: MagicMock = handle.write
        return write.call_args_list

    @property
    def write_lines(self) -> str:
        """a list of written lines (as a string)"""
        return "".join([c[0][0] for c in self.write_calls])


@pytest.fixture
def mock_file_open(mocker: MockerFixture) -> FileMock:
    return FileMock(mocker.patch("builtins.open"))
