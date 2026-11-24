"""File times and ownership taken from archive and disk-image entries, as File metadata fields.

Every helper returns a dict with any of ``creation_time``, ``access_time``, ``modification_time`` (timezone-aware
UTC datetimes) and ``security_info`` (a dict matching ``SecurityInfo``), leaving out what the format doesn't record.
"""

import tarfile
import zipfile
from datetime import UTC, datetime
from typing import Any

# ZipInfo.create_system value for archives created on Unix (external_attr then carries st_mode in the high 16 bits)
ZIP_CREATE_SYSTEM_UNIX = 3


def _from_epoch(seconds: float | int | None) -> datetime | None:
    """Epoch seconds to aware UTC; 0/None (unset in most formats) means unknown."""
    if not seconds:
        return None
    try:
        return datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError):
        return None


def zip_member_details(info: zipfile.ZipInfo) -> dict[str, Any]:
    """Modification time and Unix mode of a ZIP member.

    ZIP stores a local wall-clock time with no timezone. It is read as UTC; callers log a
    ``file_time_assumed_utc`` data issue once per archive.
    """
    details: dict[str, Any] = {}
    try:
        details["modification_time"] = datetime(*info.date_time, tzinfo=UTC)
    except (TypeError, ValueError):
        pass
    mode = info.external_attr >> 16
    if info.create_system == ZIP_CREATE_SYSTEM_UNIX and mode:
        details["security_info"] = {"mode": mode}
    return details


def tar_member_details(info: tarfile.TarInfo) -> dict[str, Any]:
    """Modification time, owner, group and mode of a tar member."""
    details: dict[str, Any] = {}
    modified = _from_epoch(info.mtime)
    if modified:
        details["modification_time"] = modified
    details["security_info"] = {
        "owner": info.uname or str(info.uid),
        "group": info.gname or str(info.gid),
        "mode": info.mode,
    }
    return details


def sevenzip_member_details(last_write: datetime | None) -> dict[str, Any]:
    """py7zr reports a member's last-write time (its ``creationtime`` attribute) as an aware UTC datetime."""
    if last_write is None:
        return {}
    if last_write.tzinfo is None:  # not produced by py7zr; guard so a naive value is never stored
        return {}
    return {"modification_time": last_write.astimezone(UTC)}


def tsk_meta_details(meta: Any) -> dict[str, Any]:
    """Times, owner, group and mode from a pytsk3 ``TSK_FS_META`` (epoch seconds, already UTC)."""
    details: dict[str, Any] = {}
    for attribute, field in (("crtime", "creation_time"), ("atime", "access_time"), ("mtime", "modification_time")):
        value = _from_epoch(getattr(meta, attribute, None))
        if value:
            details[field] = value
    security: dict[str, Any] = {}
    for attribute, field in (("uid", "owner"), ("gid", "group")):
        value = getattr(meta, attribute, None)
        if value is not None:
            security[field] = str(value)
    mode = getattr(meta, "mode", None)
    if mode is not None:
        security["mode"] = int(mode)
    if security:
        details["security_info"] = security
    return details
