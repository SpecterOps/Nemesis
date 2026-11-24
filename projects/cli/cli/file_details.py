"""Times and ownership of a local file, sent as upload metadata (creation/access/modification time, security_info)."""

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # POSIX only; absent on Windows
    import grp
    import pwd
except ImportError:  # pragma: no cover - exercised on Windows only
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


def _utc_iso(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds, UTC).isoformat()


def _owner_name(uid: int) -> str:
    if pwd is not None:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            pass
    return str(uid)


def _group_name(gid: int) -> str:
    if grp is not None:
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            pass
    return str(gid)


def local_file_details(path: Path) -> dict[str, Any]:
    """Return metadata fields describing ``path`` on this machine.

    Times are timezone-aware UTC ISO strings. Creation time comes from ``st_birthtime`` where the platform reports
    it (macOS, BSD, Windows, some Linux filesystems on Python 3.12+); it is left out otherwise, because Linux
    ``st_ctime`` is the inode change time, not creation. On Windows there are no UIDs/GIDs, so only ``mode`` is sent.
    """
    st = os.stat(path)
    details: dict[str, Any] = {
        "access_time": _utc_iso(st.st_atime),
        "modification_time": _utc_iso(st.st_mtime),
    }
    birthtime = getattr(st, "st_birthtime", None)
    if birthtime:
        details["creation_time"] = _utc_iso(birthtime)

    security: dict[str, Any] = {"mode": st.st_mode}
    if os.name == "posix":
        security["owner"] = _owner_name(st.st_uid)
        security["group"] = _group_name(st.st_gid)
    details["security_info"] = security
    return details
