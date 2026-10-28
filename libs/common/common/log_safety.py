"""Dependency-free masking for sensitive values written to logs."""


def mask(value: object) -> str:
    """Show only the first two characters followed by a fixed ten-character mask.

    Structured payloads are masked as a whole so nested secrets stay hidden.
    Only use the returned value for logging; retain the original for processing.
    """
    return str(value)[:2].ljust(2, "*") + "*" * 10
