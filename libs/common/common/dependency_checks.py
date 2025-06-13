import logging
import os
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class DependencyError(Exception):
    """Raised when required dependencies are missing."""

    def __init__(self, missing_deps: Sequence[str]):
        self.missing_deps = missing_deps
        deps_str = ", ".join(missing_deps)
        super().__init__(f"Missing required PATH dependencies: {deps_str}")


def find_missing_path_dependencies(
    commands: Sequence[str],
    *,
    raise_error: bool = True,
    search_paths: Optional[Sequence[Path]] = None,
) -> list[str]:
    """Checks if specified commands are available in system PATH.

    Args:
        commands: Sequence of command names to check
        raise_error: If True, raises DependencyError when dependencies are missing
        search_paths: Optional additional paths to search for commands

    Returns:
        List of missing dependencies (empty if all found)

    Raises:
        DependencyError: If raise_error is True and any commands are missing
    """
    missing_deps = []

    for cmd in commands:
        # Check standard PATH
        if shutil.which(cmd) is not None:
            continue

        # Check additional search paths if provided
        if search_paths:
            found = False
            for path in search_paths:
                cmd_path = path / cmd
                if cmd_path.exists() and os.access(cmd_path, os.X_OK):
                    found = True
                    break
            if found:
                continue

        missing_deps.append(cmd)

    if missing_deps:
        if raise_error:
            raise DependencyError(missing_deps)

    return missing_deps


def check_file_exists(
    filepath: str | Path,
    *,
    raise_error: bool = True,
) -> bool:
    """Checks if specified file path exists and is accessible.

    Args:
        filepath: Path to file to check (can be string or Path object)
        raise_error: If True, raises FileNotFoundError when file is missing

    Returns:
        bool: True if file exists and is accessible, False otherwise

    Raises:
        FileNotFoundError: If raise_error is True and file doesn't exist
        TypeError: If filepath is neither string nor Path
    """
    if isinstance(filepath, str):
        path = Path(filepath)
    elif isinstance(filepath, Path):
        path = filepath
    else:
        raise TypeError(f"filepath must be string or Path, not {type(filepath)}")

    exists = path.exists() and path.is_file()

    if not exists and raise_error:
        raise FileNotFoundError(f"File not found: {path}")

    return exists


def check_directory_exists(
    dirpath: str | Path,
    *,
    raise_error: bool = True,
) -> bool:
    """Checks if specified directory path exists and is accessible.

    Args:
        dirpath: Path to directory to check (can be string or Path object)
        raise_error: If True, raises NotADirectoryError when directory is missing

    Returns:
        bool: True if directory exists and is accessible, False otherwise

    Raises:
        NotADirectoryError: If raise_error is True and directory doesn't exist
        TypeError: If dirpath is neither string nor Path
    """
    if isinstance(dirpath, str):
        path = Path(dirpath)
    elif isinstance(dirpath, Path):
        path = dirpath
    else:
        raise TypeError(f"dirpath must be string or Path, not {type(dirpath)}")

    exists = path.exists() and path.is_dir()

    if not exists and raise_error:
        raise NotADirectoryError(f"Directory not found: {path}")

    return exists
