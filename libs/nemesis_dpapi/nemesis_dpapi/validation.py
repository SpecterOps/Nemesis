"""Validation helpers for DPAPI operations."""

from typing import Any

from Crypto.Hash import SHA1


def validate_and_calculate_sha1(
    plaintext_key: bytes | None,
    plaintext_key_sha1: bytes | None,
) -> bytes | None:
    """Validate and/or calculate SHA1 of plaintext key.

    This function enforces that if a plaintext_key is provided, its SHA1 hash is
    correctly calculated and matches any provided plaintext_key_sha1. This ensures
    data integrity and prevents accepting mismatched key/hash pairs.

    Rules:
    - If plaintext_key provided: calculate SHA1, verify if sha1 also provided
    - If only sha1 provided: return it (valid scenario for SHA1-only updates)
    - If neither provided: return None

    Args:
        plaintext_key: The plaintext masterkey bytes (optional)
        plaintext_key_sha1: The SHA1 hash of the plaintext key (optional)

    Returns:
        The validated/calculated SHA1 hash, or None if neither input provided

    Raises:
        ValueError: If provided sha1 doesn't match calculated sha1 from plaintext_key

    Examples:
        >>> # Auto-calculate SHA1
        >>> sha1 = validate_and_calculate_sha1(b"mykey", None)

        >>> # Verify provided SHA1 matches
        >>> sha1 = validate_and_calculate_sha1(b"mykey", expected_sha1)

        >>> # SHA1-only update
        >>> sha1 = validate_and_calculate_sha1(None, known_sha1)
    """
    if plaintext_key is not None:
        calculated = SHA1.new(plaintext_key).digest()
        if plaintext_key_sha1 is not None:
            if calculated != plaintext_key_sha1:
                raise ValueError("Provided plaintext_key_sha1 does not match calculated SHA1 of plaintext_key")
        return calculated
    return plaintext_key_sha1


def validate_no_empty_string(value: str | None, field_name: str) -> None:
    """Validate that string field is not empty string (NULL or non-empty only).

    Empty strings are not allowed as they can be ambiguous with NULL values.
    Fields should either be NULL (unset) or contain a non-empty string.

    Args:
        value: The string value to validate (can be None)
        field_name: The name of the field being validated (for error messages)

    Raises:
        ValueError: If value is an empty string

    Examples:
        >>> validate_no_empty_string(None, "domain_controller")  # OK
        >>> validate_no_empty_string("DC01", "domain_controller")  # OK
        >>> validate_no_empty_string("", "domain_controller")  # Raises ValueError
    """
    if value == "":
        raise ValueError(f"{field_name} cannot be empty string (use None for unset)")


def check_write_once_conflicts(
    existing: Any,
    new: Any,
    fields: list[str],
) -> list[str]:
    """Check for write-once conflicts between existing and new records.

    Compares specified fields between an existing record and a new record to detect
    write-once violations. A violation occurs when:
    - The existing field has a non-NULL value
    - The new field has a different value (including NULL)

    This enforces write-once semantics where fields can only be set once and cannot
    be changed afterward.

    Args:
        existing: The existing record object
        new: The new record object to compare against
        fields: List of field names to check for conflicts

    Returns:
        List of field names that have write-once conflicts (empty if no conflicts)

    Examples:
        >>> conflicts = check_write_once_conflicts(
        ...     existing_masterkey,
        ...     new_masterkey,
        ...     ["plaintext_key", "backup_key_guid"]
        ... )
        >>> if conflicts:
        ...     raise WriteOnceViolationError("masterkey", guid, conflicts)
    """
    conflicts = []
    for field in fields:
        existing_val = getattr(existing, field)
        new_val = getattr(new, field)

        # Write-once violation: existing is not NULL and differs from new value
        # This includes the case where new value is NULL (attempting to clear a field)
        if existing_val is not None and existing_val != new_val:
            conflicts.append(field)

    return conflicts
