"""Validation helpers for identifiers received from C2 servers.

C2 download IDs are attacker-influenceable data (a compromised or malicious C2
server, or a tampered API response) and must never be trusted when building
local filesystem paths or temp file names.
"""

import re
from pathlib import Path

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def is_safe_c2_id(value: object) -> bool:
    """Return True if value is a plain identifier usable as a single path component."""
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        return False
    return value not in (".", "..")


def safe_child_path(base_dir: Path, c2_id: object) -> Path | None:
    """Return base_dir/c2_id if the ID is safe and the result stays inside base_dir.

    Returns None for unsafe IDs or when the resolved path (following symlinks)
    escapes base_dir.
    """
    if not is_safe_c2_id(c2_id):
        return None
    base_resolved = base_dir.resolve()
    candidate = base_dir / str(c2_id)
    if not candidate.resolve().is_relative_to(base_resolved):
        return None
    return candidate
