# Standard Libraries
import re
from typing import List, Optional, Tuple

REGISTRY_HIVE_NAME_MAP: dict[str, str] = {
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKEY_CURRENT_USER": "HKCU",
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKEY_CURRENT_CONFIG": "HKCC",
    "HKEY_PERFORMANCE_DATA": "HKPD",
    "HKEY_PERFORMANCE_TEXT": "HKPT",
    "HKEY_DYN_DATA": "HKDD",
    "HKEY_USERS": "HKU",
}
REGISTRY_HIVE_SHORT_NAMES: List[str] = list(REGISTRY_HIVE_NAME_MAP.values())
REGISTRY_HIVE_LONG_NAMES: List[str] = list(REGISTRY_HIVE_NAME_MAP.keys())


def normalize_slashes(path: str) -> str:
    """Normalizes a path by removing duplicate slashes and ensuring it does not end with a slash

    Args:
        path (str): The path to normalize

    Returns:
        The normalized path
    """

    # remove duplicate backslashes
    path = re.sub(r"\\+", r"\\", path)

    # Ensure the path does not end with a slash
    if path.endswith("\\"):
        path = path[:-1]

    return path


def normalize_hive_name(path: str) -> str:
    """Normalizes the hive name in a registry path to its short name

    Args:
        path (str): The absolute registry path to a normalized registry path

    Raises:
        ValueError: If the hive is not specified in the path
        ValueError: If the hive is not a valid short or long hive name

    Returns:
        The normalized registry path
    """
    hive, remaining_path = parse_next_subkey(path)
    if hive is None:
        raise ValueError(f"No registry hive specified. Path: {path}")

    # Don't need to check if remaining_path is None since
    # hives themselves can have registry values

    # Normalize the hive name to the short name
    hive = hive.upper()
    if hive in REGISTRY_HIVE_SHORT_NAMES:
        # Already the short name
        pass
    elif hive in REGISTRY_HIVE_LONG_NAMES:
        # Convert the long name to the short name
        hive = REGISTRY_HIVE_NAME_MAP[hive]
    else:
        raise ValueError(f"Invalid registry hive. Path: {path}")

    if remaining_path is None:
        return hive
    else:
        return hive + "\\" + remaining_path


def normalize_registry_path(path: str) -> str:
    """Normalizes an absolute registry path, converting it
    to the short name of the hive, removing double slashes,
    and ensuring it does not end with a slash

    Args:
        path (str): An absolute registry path

    Returns:
        The normalized registry path.

    Raises:
        ValueError: If the path does not contain a registry hive
    """

    path = normalize_slashes(path)
    path = normalize_hive_name(path)
    return path


def parse_next_subkey(path: str) -> Tuple[str, Optional[str]]:
    """Parses the next key name from a given registry path and returns the subkey and the remaining unparsed registry path.

    Args:
        path (str): Normalized registry path. Example: "hklm\\system\\currentcontrolset\\services\\lanmanserver\\shares\\security"

    Returns:
        Tuple[Optional[str], Optional[str]]: (subkey, remaining_path) - The subkey and the remaining unparsed registry path.

        If there is no subkey, then the subkey will be None.
        If there is no remaining path, then the remaining path will be None.

    Raises:
        ValueError: If the path is empty
    """

    if not path:
        raise ValueError("path cannot be empty")

    slash_index = path.find("\\")

    if slash_index == -1:
        # if there is no slash, then there is no more subkeys (example: path = "security")
        return (path, None)

    subkey = path[:slash_index]
    remaining_path = path[slash_index + 1 :]

    if not remaining_path:
        remaining_path = None

    return (subkey, remaining_path)
