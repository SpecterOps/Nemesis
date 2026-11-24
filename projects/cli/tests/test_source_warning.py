"""submit and monitor warn when no --source is given (Nemesis then records unknown://unknown)."""

from unittest.mock import MagicMock, patch

import pytest
from cli import submit as submit_module
from cli.monitor import monitor_main
from cli.submit import UNKNOWN_SOURCE_WARNING, warn_if_source_missing


@pytest.mark.parametrize("source", [None, ""])
def test_warns_without_source(source):
    with patch.object(submit_module, "logger") as logger:
        warn_if_source_missing(source)
    logger.warning.assert_called_once_with(UNKNOWN_SOURCE_WARNING)


def test_no_warning_with_source():
    with patch.object(submit_module, "logger") as logger:
        warn_if_source_missing("host://WS01")
    logger.warning.assert_not_called()


@pytest.mark.parametrize(("source", "warned"), [(None, True), ("host://WS01", False)])
def test_submit_main_warns_once(tmp_path, source, warned):
    target = tmp_path / "f.txt"
    target.write_text("x")
    with (
        patch.object(submit_module, "logger") as logger,
        patch.object(submit_module, "submit_files", return_value=True),
    ):
        submit_module.submit_main(
            False, (str(target),), "h:1", False, 1, "u", "p", "proj", "agent", None, False, source=source
        )
    assert (UNKNOWN_SOURCE_WARNING in [c.args[0] for c in logger.warning.call_args_list]) is warned


@pytest.mark.parametrize(("source", "warned"), [(None, True), ("host://WS01", False)])
@patch("cli.monitor.Observer")
@patch("cli.monitor.time.sleep", side_effect=KeyboardInterrupt)
@patch("cli.monitor.submit_files", return_value=True)
def test_monitor_main_warns_once(_submit, _sleep, _observer, tmp_path, source, warned):
    logger = MagicMock()
    with patch("cli.monitor.setup_logging", return_value=logger):
        monitor_main(str(tmp_path), False, "h:1", "u", "p", "proj", "agent", True, 1, False, source)
    assert (UNKNOWN_SOURCE_WARNING in [c.args[0] for c in logger.warning.call_args_list]) is warned
