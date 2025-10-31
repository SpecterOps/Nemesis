import hashlib
import io
import posixpath
import re
import subprocess
from typing import BinaryIO


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
        "rtf|sdw|stw|sxw|uot|vor|wps|epub|emf|eps|fodg|met|odd|otg|dotx|"
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


def can_extract_plaintext(mime_type: str) -> bool:
    """Returns True if the file's mime type can be used with Tika."""

    # from https://tika.apache.org/2.8.0/formats.html#Full_list_of_Supported_Formats_in_standard_artifacts
    supported_mime_types = {
        "text/csv": 1,
        # "text/plain": 1,
        "text/html": 1,
        "application/vnd.wap.xhtml+xml": 1,
        "application/x-asp": 1,
        "application/xhtml+xml": 1,
        "image/png": 1,
        "image/vnd.wap.wbmp": 1,
        "image/x-jbig2": 1,
        "image/bmp": 1,
        "image/x-xcf": 1,
        "image/gif": 1,
        "image/x-ms-bmp": 1,
        "image/jpeg": 1,
        # "application/mbox": 1,
        "image/emf": 1,
        # "application/x-msaccess": 1,
        "application/x-tika-msoffice-embedded; format=ole10_native": 1,
        "application/msword": 1,
        "application/vnd.visio": 1,
        "application/x-tika-ole-drm-encrypted": 1,
        "application/vnd.ms-project": 1,
        "application/x-tika-msworks-spreadsheet": 1,
        "application/x-mspublisher": 1,
        "application/vnd.ms-powerpoint": 1,
        "application/x-tika-msoffice": 1,
        "application/sldworks": 1,
        "application/x-tika-ooxml-protected": 1,
        "application/vnd.ms-excel": 1,
        # "application/vnd.ms-outlook": 1,
        "application/vnd.ms-excel.workspace.3": 1,
        "application/vnd.ms-excel.workspace.4": 1,
        "application/vnd.ms-excel.sheet.2": 1,
        "application/vnd.ms-excel.sheet.3": 1,
        "application/vnd.ms-excel.sheet.4": 1,
        "image/wmf": 1,
        "application/vnd.ms-htmlhelp": 1,
        "application/x-chm": 1,
        "application/chm": 1,
        "application/onenote; format=one": 1,
        "application/vnd.ms-powerpoint.template.macroenabled.12": 1,
        "application/vnd.ms-excel.addin.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template": 1,
        "application/vnd.ms-excel.sheet.binary.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": 1,
        "application/vnd.ms-powerpoint.slide.macroenabled.12": 1,
        "application/vnd.ms-visio.drawing": 1,
        "application/vnd.ms-powerpoint.slideshow.macroenabled.12": 1,
        "application/vnd.ms-powerpoint.presentation.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.slide": 1,
        "application/vnd.ms-excel.sheet.macroenabled.12": 1,
        "application/vnd.ms-word.template.macroenabled.12": 1,
        "application/vnd.ms-word.document.macroenabled.12": 1,
        "application/vnd.ms-powerpoint.addin.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template": 1,
        "application/vnd.ms-xpsdocument": 1,
        "application/vnd.ms-visio.drawing.macroenabled.12": 1,
        "application/vnd.ms-visio.template.macroenabled.12": 1,
        "model/vnd.dwfx+xps": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.template": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": 1,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": 1,
        "application/vnd.ms-visio.stencil": 1,
        "application/vnd.ms-visio.template": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow": 1,
        "application/vnd.ms-visio.stencil.macroenabled.12": 1,
        "application/vnd.ms-excel.template.macroenabled.12": 1,
        "application/vnd.ms-word2006ml": 1,
        "application/vnd.ms-outlook-pst": 1,
        "application/rtf": 1,
        "application/vnd.ms-wordml": 1,
        "image/ocr-x-portable-pixmap": 1,
        "image/ocr-jpx": 1,
        "image/x-portable-pixmap": 1,
        "image/ocr-jpeg": 1,
        "image/ocr-jp2": 1,
        "image/jpx": 1,
        "image/ocr-png": 1,
        "image/ocr-tiff": 1,
        "image/ocr-gif": 1,
        "image/ocr-bmp": 1,
        "image/jp2": 1,
        "application/pdf": 1,
        "application/vnd.wordperfect; version=5.1": 1,
        "application/vnd.wordperfect; version=5.0": 1,
        "application/vnd.wordperfect; version=6.x": 1,
        "application/xml": 1,
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


def get_file_extension(filepath):
    # Get just the final filename component of the path
    base_name = posixpath.basename(filepath)

    # Split on the last dot, but only if the dot isn't the first character
    if base_name.startswith(".") or "." not in base_name:
        return ""

    name_parts = base_name.split(".")
    if len(name_parts) > 1:
        return "." + name_parts[-1]
    return ""


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


def extract_all_strings(filename: str, min_len: int = 5):
    """
    Returns a combined list of all single-byte ASCII strings
    and UTF-16 (both LE and BE) strings found by the `strings` utility.
    """
    commands = [
        ["strings", "-a", "-n", str(min_len), filename],  # ASCII
        ["strings", "-a", "-n", str(min_len), "-e", "l", filename],  # UTF-16 LE
        ["strings", "-a", "-n", str(min_len), "-e", "b", filename],  # UTF-16 BE
    ]

    all_strings = []
    for cmd in commands:
        result = subprocess.run(cmd, capture_output=True, text=True)
        # Each line of stdout is one string
        lines = result.stdout.splitlines()
        all_strings.extend(lines)

    # Optionally, deduplicate if you want unique strings only:
    # all_strings = list(set(all_strings))

    return all_strings


def create_text_reader(binary_file: BinaryIO) -> io.TextIOWrapper:
    """Creates a text reader that handles BOMs and mixed content"""

    bom_check = binary_file.read(4)
    binary_file.seek(0)  # Reset to start

    if bom_check.startswith(b"\xff\xfe"):
        return io.TextIOWrapper(binary_file, encoding="utf-16le")
    elif bom_check.startswith(b"\xfe\xff"):
        return io.TextIOWrapper(binary_file, encoding="utf-16be")
    elif bom_check.startswith(b"\xef\xbb\xbf"):
        return io.TextIOWrapper(binary_file, encoding="utf-8-sig")
    else:
        return io.TextIOWrapper(binary_file, encoding="utf-8", errors="replace")


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
    Handles null bytes and other problematic characters.

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
        return cleaned
    else:
        # Return non-string primitives as-is
        return obj
