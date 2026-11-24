import hashlib
import io
import json
import math
import posixpath
import re
from dataclasses import asdict, dataclass
from typing import Any, BinaryIO
from uuid import UUID

from common.data_issues import DataIssueKind, log_data_issue
from pydantic import BaseModel
from pydantic_core import to_jsonable_python


def calculate_file_hash(file_path: str, hash_type: str) -> str:
    """
    Calculate the hash of a file using the specified algorithm.

    Args:
        file_path (str): Path to the file
        hash_type (str): Type of hash to calculate ('md5', 'sha1', or 'sha256')

    Returns:
        str: Hexadecimal string of the calculated hash
    """
    hash_funcs = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}

    hash_func = hash_funcs.get(hash_type.lower())
    if not hash_func:
        raise ValueError(f"Unsupported hash type: {hash_type}")

    hasher = hash_func()
    with open(file_path, "rb") as f:
        # Read the file in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def can_convert_to_pdf(file_path: str) -> bool:
    """Returns True if the supplied file_path matches an extension that Gotenberg can convert."""
    path_regex = (
        "^.*\\.(bib|doc|docx|fodt|html|ltx|txt|odt|ott|pdb|psw|odg|"
        "rtf|sdw|stw|sxw|uot|vor|wps|emf|eps|fodg|met|odd|otg|dotx|"
        "pbm|pct|pgm|ppm|ras|std|svg|svm|swf|sxd|sxw|tiff|xhtml|xpm|xltx|"
        "fodp|potm|pot|pptx|pps|ppt|pwp|sda|sdd|sti|sxi|uop|wmf|dbf|"
        "dif|fods|ods|ots|pxl|sdc|slk|stc|sxc|uos|xls|xlt|xlsx|odp)$"
    )
    return re.match(path_regex, file_path, re.IGNORECASE) is not None


def is_container(mime_type: str) -> bool:
    """Returns true if the mime type is a container we can currently extract."""

    supported_mime_types = {
        "application/zip",  # .zip
        "application/x-7z-compressed",  # .7z
        "application/x-rar",  # .rar
        "application/x-tar",  # .tar
        # 'application/x-bzip2',
        "application/x-gzip",  # .tar.gz
        "application/gzip",  # .tar.gz
        # 'application/java-archive', # .JAR
        "application/vnd.microsoft-cab",  # .cab
        # 'application/x-iso9660-image',
        # 'application/x-debian-package',
        # 'application/x-rpm'
    }

    return mime_type in supported_mime_types


def is_text_file(file_path: str, sample_size: int = 1024):
    """
    Determines if a file is plaintext by checking for binary characters
    in a sample of its contents.

    Args:
        file_path: Path to the file to check
        sample_size: Number of bytes to check (default 1024)

    Returns:
        bool: True if the file appears to be text, False if likely binary
    """
    try:
        with open(file_path, "rb") as f:
            # Read a sample of the file
            sample = f.read(sample_size)

        # Check for presence of null bytes
        if b"\x00" in sample:
            return False

        # Try to decode as utf-8
        try:
            sample.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False

    except OSError:
        return False


def is_plaintext(data: bytes, sample_size: int = 1024) -> bool:
    """
    Determines if raw bytes represent plaintext by checking for binary characters
    in a sample of the data.

    Args:
        data: Raw bytes to check
        sample_size: Number of bytes to check from the beginning (default 1024)

    Returns:
        bool: True if the data appears to be text, False if likely binary
    """
    if not data:
        return True  # Empty data is considered text

    # Take a sample from the beginning of the data
    sample = data[:sample_size]

    # Check for presence of null bytes
    if b"\x00" in sample:
        return False

    # Try to decode as utf-8
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def sanitize_file_path(file_path: str, num_chars=5):
    """
    Replaces all but the first `num_chars` characters of a file path string with *'s,
    while preserving the file extension.

    Args:
        file_path (str): The file path to sanitize
        num_chars (int): Number of characters to keep visible at the start

    Returns:
        str: Sanitized file path with preserved extension
    """
    if not file_path:
        return file_path

    # Split the path into name and extension
    base_name, *extension = file_path.rsplit(".", 1)

    # Sanitize the base name
    sanitized_base = base_name[0:num_chars] + len(base_name[num_chars:]) * "*"

    # Return with extension if it exists, otherwise just the sanitized base
    return f"{sanitized_base}.{extension[0]}" if extension else sanitized_base


def require_uuid(value: UUID) -> UUID:
    """Return ``value`` if it is a ``uuid.UUID``; raise TypeError otherwise.

    Object IDs are ``UUID`` end to end. Used at boundaries (storage, DB lookups, caches) to catch a ``str`` that
    slipped through an untyped path (e.g. a dict read) instead of silently using it.
    """
    if not isinstance(value, UUID):
        raise TypeError(f"object IDs must be uuid.UUID, got {type(value).__name__}")
    return value


def as_uuid(value: object) -> UUID:
    """Convert an object ID read from an untyped boundary (Dapr workflow/activity input, a JSON payload, a dict row)
    into a ``UUID``. Raises ValueError for anything that isn't a UUID or a UUID string."""
    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        return UUID(value)
    raise ValueError(f"expected a UUID or UUID string, got {type(value).__name__}")


def jsonable(obj: Any) -> Any:
    """JSON-compatible copy of ``obj`` (UUID → str, datetime → ISO, models → dicts) for Dapr inputs and payloads."""
    return to_jsonable_python(obj)


# files_enriched.extension is VARCHAR(50)
MAX_EXTENSION_LENGTH = 50


def get_file_extension(filepath: str, *, object_id: UUID | None = None) -> str:
    """Return the file's extension including the dot (``".txt"``), or ``""`` if it has none.

    A suffix longer than MAX_EXTENSION_LENGTH (e.g. ``report.2024-01-01_backup_copy_of_...``) is not a real extension
    and would not fit the column, so it is treated as no extension and logged as an extension_too_long data issue.
    """
    # Get just the final filename component of the path
    base_name = posixpath.basename(filepath)

    # Split on the last dot, but only if the dot isn't the first character
    if base_name.startswith(".") or "." not in base_name:
        return ""

    extension = "." + base_name.rsplit(".", 1)[-1]
    if len(extension) > MAX_EXTENSION_LENGTH:
        log_data_issue(
            DataIssueKind.EXTENSION_TOO_LONG,
            field="files_enriched.extension",
            object_id=object_id,
            length=len(extension),
            limit=MAX_EXTENSION_LENGTH,
            prefix=extension[:20],
        )
        return ""
    return extension


def get_drive_from_path(path: str) -> str | None:
    """
    Extract Windows drive letter from a file path.

    Supports two path formats:
    1. POSIX-style with leading slash: "/C:/Users/..." or "/D:/Data/..."
    2. Windows-style without leading slash: "C:/Users/..." or "D:/Data/..."

    Args:
        path: File path string to parse

    Returns:
        str | None: Drive letter with colon, or None if no valid drive found
            - For POSIX-style paths: Returns with leading slash (e.g., "/C:", "/D:")
            - For Windows-style paths: Returns without leading slash (e.g., "C:", "D:")

    Examples:
        >>> get_drive_from_path("/C:/Users/john/file.txt")
        '/C:'
        >>> get_drive_from_path("C:/Users/john/file.txt")
        'C:'
        >>> get_drive_from_path("/D:/Data/files")
        '/D:'
        >>> get_drive_from_path("invalid/path")
        None

    Supported drive letters: A-Z (case-insensitive)
    """
    parts = path.split("/")

    # Handle paths without leading slash (e.g., "C:/Users/...")
    if len(parts) >= 1 and parts[0]:
        drive_part = parts[0]

        # Validate drive part
        if not drive_part:
            return None

        # Must be exactly 2 characters: letter + colon
        if len(drive_part) != 2:
            return None

        # Second character must be ':'
        if drive_part[1] != ":":
            return None

        # First character must be a letter (A-Z or a-z)
        if not drive_part[0].isalpha():
            return None

        # Return drive without trailing slash for paths without leading slash
        return drive_part

    # For paths like "/C:/Users/...", parts[0] is empty and parts[1] contains the drive
    if len(parts) >= 2:
        drive_part = parts[1]

        # Validate drive part
        if not drive_part:
            return None

        # Must be exactly 2 characters: letter + colon
        if len(drive_part) != 2:
            return None

        # Second character must be ':'
        if drive_part[1] != ":":
            return None

        # First character must be a letter (A-Z or a-z)
        if not drive_part[0].isalpha():
            return None

        # Return "/" + drive letter with colon
        # e.g., "C:" -> "/C:"
        return f"/{drive_part}"

    return None


def create_text_reader(binary_file: BinaryIO) -> io.TextIOWrapper:
    """Creates a text reader that handles BOMs and mixed content.

    Every encoding uses errors="replace": `file` can call content text/plain even when it holds bytes that are invalid
    in its encoding (e.g. a UTF-8 BOM followed by 0xFF), and a strict decode would raise and abort the caller.
    """

    bom_check = binary_file.read(4)
    binary_file.seek(0)  # Reset to start

    if bom_check.startswith(b"\xff\xfe"):
        encoding = "utf-16le"
    elif bom_check.startswith(b"\xfe\xff"):
        encoding = "utf-16be"
    elif bom_check.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    else:
        encoding = "utf-8"
    return io.TextIOWrapper(binary_file, encoding=encoding, errors="replace")


def escape_markdown(text):
    """
    Escapes markdown control characters in text by adding backslashes.
    """
    markdown_chars = ["\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", ".", "!", "|"]
    escaped_text = ""
    for char in text:
        if char in markdown_chars:
            escaped_text += "\\" + char
        else:
            escaped_text += char
    return escaped_text


def sanitize_for_jsonb(obj):
    """
    Recursively sanitize a Python object (dict, list, or primitive) to be safe for PostgreSQL JSONB.
    Handles null bytes, invalid Unicode surrogates, and other problematic characters.

    Args:
        obj: The object to sanitize (can be a dict, list, or primitive type)

    Returns:
        The sanitized object with the same structure but cleaned strings
    """
    if isinstance(obj, dict):
        return {key: sanitize_for_jsonb(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_jsonb(item) for item in obj]
    elif isinstance(obj, str):
        # Replace null bytes
        cleaned = obj.replace("\x00", "")
        # Replace other problematic control characters
        cleaned = "".join(char for char in cleaned if char >= " " or char in "\n\r\t")
        # Remove unpaired Unicode surrogates (U+D800 to U+DFFF)
        # These are invalid in JSON and will cause PostgreSQL JSONB errors
        cleaned = "".join(char for char in cleaned if not (0xD800 <= ord(char) <= 0xDFFF))
        return cleaned
    else:
        # Return non-string primitives as-is
        return obj


@dataclass
class SanitizeReport:
    """Counts of what sanitize_for_jsonb_report changed; all zero means the data was stored unchanged."""

    nul_bytes: int = 0
    control_chars: int = 0
    surrogates: int = 0
    non_json_values: int = 0

    @property
    def changed(self) -> bool:
        return any(asdict(self).values())

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


_JSON_SCALARS = (str, int, float, bool, type(None))


def _clean_string(value: str, report: SanitizeReport) -> str:
    out = []
    for char in value:
        code = ord(char)
        if code == 0:
            report.nul_bytes += 1
        elif 0xD800 <= code <= 0xDFFF:
            report.surrogates += 1
        elif char < " " and char not in "\n\r\t":
            report.control_chars += 1
        else:
            out.append(char)
    return "".join(out)


def _sanitize(obj: Any, report: SanitizeReport) -> Any:
    if isinstance(obj, BaseModel):
        return _sanitize(obj.model_dump(mode="json"), report)
    if isinstance(obj, dict):
        clean = {}
        for key, value in obj.items():
            if not isinstance(key, str):
                report.non_json_values += 1
                key = str(key)
            clean[_clean_string(key, report)] = _sanitize(value, report)
        return clean
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_sanitize(item, report) for item in obj]
    if isinstance(obj, str):
        return _clean_string(obj, report)
    if isinstance(obj, float) and not math.isfinite(obj):
        # NaN/Infinity are not valid JSON and PostgreSQL rejects them in JSONB
        report.non_json_values += 1
        return None
    if isinstance(obj, _JSON_SCALARS):
        return obj
    if isinstance(obj, (bytes, bytearray, memoryview)):
        report.non_json_values += 1
        return bytes(obj).hex()
    try:
        # UUID, datetime, date, Enum, Decimal, Path, ... have a standard JSON form
        return _sanitize(to_jsonable_python(obj), report)
    except Exception:
        report.non_json_values += 1
        return _clean_string(str(obj), report)


def sanitize_for_jsonb_report(obj: Any) -> tuple[Any, SanitizeReport]:
    """Return a JSON-compatible copy of ``obj`` that PostgreSQL JSONB accepts, plus what had to change.

    Removes NUL bytes, control characters (other than newline, carriage return and tab) and lone surrogates from
    strings; converts models, UUIDs, datetimes and enums to their JSON form; hex-encodes bytes; turns NaN/Infinity
    into null; stringifies anything else and non-string dict keys.
    """
    report = SanitizeReport()
    return _sanitize(obj, report), report


def jsonb_dumps(obj: Any, *, column: str, object_id: UUID | None = None, **context: Any) -> str:
    """Serialize ``obj`` for a JSONB column, logging a jsonb_sanitized data issue if anything had to change.

    Args:
        obj: Value to store (dict, list, model, ...).
        column: Destination column, e.g. ``findings.raw_data`` (used in the log).
        object_id: File the value belongs to, for the log.
        context: Extra log context (e.g. ``finding_name``).
    """
    clean, report = sanitize_for_jsonb_report(obj)
    if report.changed:
        log_data_issue(DataIssueKind.JSONB_SANITIZED, field=column, object_id=object_id, **report.as_dict(), **context)
    return json.dumps(clean)
