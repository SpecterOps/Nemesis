"""Core data models for DPAPI library."""

import re
from typing import Annotated

from pydantic import BeforeValidator


def validate_windows_sid(value: str) -> str:
    """Validate that a string is a valid Windows SID format.

    Windows SIDs have the format: S-R-I-S-S-...-S
    Where:
    - S = literal 'S'
    - R = revision (usually 1)
    - I = identifier authority (48-bit number)
    - S = subauthority values (32-bit numbers)

    Examples:
    - S-1-5-21-1234567890-1234567890-1234567890-1001 (domain user)
    - S-1-5-18 (local system)
    - S-1-5-32-544 (builtin administrators)
    """
    if not isinstance(value, str):
        raise ValueError("SID must be a string")

    # Basic format check: starts with S-, all parts are numeric except first
    sid_pattern = r"^S-\d+(-\d+)*$"

    if not re.match(sid_pattern, value):
        raise ValueError(f"Invalid Windows SID format: {value}")

    # Split and validate components
    parts = value.split("-")

    # Must have at least S-R-I-S (4 parts after splitting - need at least one subauthority)
    if len(parts) < 4:
        raise ValueError(f"SID must have at least one subauthority: {value}")

    # First part must be 'S'
    if parts[0] != "S":
        raise ValueError(f"SID must start with 'S': {value}")

    # Second part is revision (should be 1)
    try:
        revision = int(parts[1])
        if revision != 1:
            raise ValueError(f"SID revision must be 1, got {revision}: {value}")
    except ValueError as e:
        # Re-raise specific revision errors, but catch non-numeric revision errors
        if "SID revision must be 1" in str(e):
            raise e
        raise ValueError(f"Invalid SID revision: {value}") from e

    # Validate all numeric parts are valid integers
    for i, part in enumerate(parts[2:], start=2):
        try:
            num_val = int(part)
            # Authority and subauthority values should be non-negative
            if num_val < 0:
                raise ValueError(f"SID component at position {i} must be non-negative: {value}")
        except ValueError as e:
            raise ValueError(f"Invalid numeric component in SID at position {i}: {value}") from e

    return value


Sid = Annotated[str, BeforeValidator(validate_windows_sid)]
