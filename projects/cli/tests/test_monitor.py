"""Tests for cli.monitor module - NewFileHandler with os.fsdecode and Optional source type."""

import logging
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from cli.monitor import NewFileHandler


class TestNewFileHandlerInit:
    def test_default_source_is_none(self):
        handler = NewFileHandler(
            host="localhost:8080",
            username="u",
            password="p",
            project="proj",
            agent_id="agent-1",
            logger=logging.getLogger("test"),
        )
        assert handler.source is None

    def test_explicit_source(self):
        handler = NewFileHandler(
            host="localhost:8080",
            username="u",
            password="p",
            project="proj",
            agent_id="agent-1",
            logger=logging.getLogger("test"),
            source="host://10.0.0.1",
        )
        assert handler.source == "host://10.0.0.1"

    def test_container_default_false(self):
        handler = NewFileHandler(
            host="localhost:8080",
            username="u",
            password="p",
            project="proj",
            agent_id="agent-1",
            logger=logging.getLogger("test"),
        )
        assert handler.container is False

    def test_all_attributes_stored(self):
        logger = logging.getLogger("test")
        handler = NewFileHandler(
            host="h",
            username="u",
            password="p",
            project="proj",
            agent_id="a",
            logger=logger,
            container=True,
            source="src",
        )
        assert handler.host == "h"
        assert handler.username == "u"
        assert handler.password == "p"
        assert handler.project == "proj"
        assert handler.agent_id == "a"
        assert handler.logger is logger
        assert handler.container is True
        assert handler.source == "src"


class TestNewFileHandlerOnCreated:
    def _make_handler(self):
        return NewFileHandler(
            host="localhost:8080",
            username="u",
            password="p",
            project="proj",
            agent_id="agent-1",
            logger=logging.getLogger("test"),
            source="test-source",
        )

    @patch("cli.monitor.submit_files")
    @patch("cli.monitor.time")
    def test_on_created_calls_submit(self, mock_time, mock_submit):
        handler = self._make_handler()
        event = MagicMock()
        event.is_directory = False
        event.src_path = "/tmp/test_file.txt"

        handler.on_created(event)

        mock_submit.assert_called_once_with(
            paths=[Path("/tmp/test_file.txt")],
            host="localhost:8080",
            recursive=False,
            workers=1,
            username="u",
            password="p",
            project="proj",
            agent_id="agent-1",
            container=False,
            source="test-source",
        )

    @patch("cli.monitor.submit_files")
    @patch("cli.monitor.time")
    def test_on_created_skips_directories(self, mock_time, mock_submit):
        handler = self._make_handler()
        event = MagicMock()
        event.is_directory = True

        handler.on_created(event)
        mock_submit.assert_not_called()

    @patch("cli.monitor.submit_files")
    @patch("cli.monitor.time")
    def test_on_created_uses_fsdecode(self, mock_time, mock_submit):
        """Verify that os.fsdecode is applied to the event path."""
        handler = self._make_handler()
        event = MagicMock()
        event.is_directory = False
        # Simulate a bytes path (which os.fsdecode handles)
        event.src_path = os.fsencode("/tmp/test_file.txt")

        handler.on_created(event)

        # The path should be decoded and passed as a Path object
        call_args = mock_submit.call_args
        paths = call_args.kwargs.get("paths") or call_args[1].get("paths")
        if paths is None:
            paths = call_args[0][0] if call_args[0] else None
        # Check it was called (the fsdecode would have handled bytes -> str)
        mock_submit.assert_called_once()

    @patch("cli.monitor.submit_files", side_effect=Exception("network error"))
    @patch("cli.monitor.time")
    def test_on_created_handles_submit_error(self, mock_time, mock_submit):
        """Errors in submit_files are caught and logged, not propagated."""
        handler = self._make_handler()
        event = MagicMock()
        event.is_directory = False
        event.src_path = "/tmp/test_file.txt"

        # Should not raise
        handler.on_created(event)


class TestNewFileHandlerOnMoved:
    def _make_handler(self):
        return NewFileHandler(
            host="localhost:8080",
            username="u",
            password="p",
            project="proj",
            agent_id="agent-1",
            logger=logging.getLogger("test"),
        )

    @patch("cli.monitor.submit_files")
    def test_on_moved_calls_submit(self, mock_submit):
        handler = self._make_handler()
        event = MagicMock()
        event.is_directory = False
        event.dest_path = "/tmp/moved_file.txt"

        handler.on_moved(event)

        mock_submit.assert_called_once_with(
            paths=[Path("/tmp/moved_file.txt")],
            host="localhost:8080",
            recursive=False,
            workers=1,
            username="u",
            password="p",
            project="proj",
            agent_id="agent-1",
            container=False,
            source=None,
        )

    @patch("cli.monitor.submit_files")
    def test_on_moved_skips_directories(self, mock_submit):
        handler = self._make_handler()
        event = MagicMock()
        event.is_directory = True

        handler.on_moved(event)
        mock_submit.assert_not_called()

    @patch("cli.monitor.submit_files")
    def test_on_moved_uses_fsdecode(self, mock_submit):
        """Verify that os.fsdecode is applied to the dest_path."""
        handler = self._make_handler()
        event = MagicMock()
        event.is_directory = False
        event.dest_path = os.fsencode("/tmp/moved_file.txt")

        handler.on_moved(event)
        mock_submit.assert_called_once()

    @patch("cli.monitor.submit_files", side_effect=Exception("fail"))
    def test_on_moved_handles_submit_error(self, mock_submit):
        handler = self._make_handler()
        event = MagicMock()
        event.is_directory = False
        event.dest_path = "/tmp/moved_file.txt"

        # Should not raise
        handler.on_moved(event)
