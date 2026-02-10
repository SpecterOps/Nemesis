"""Test harness for standalone enrichment module testing.

This package provides mocks and utilities for testing enrichment modules
without requiring the full Nemesis infrastructure (Minio, PostgreSQL, Dapr).

Usage:
    from tests.harness import ModuleTestHarness, FileEnrichedFactory

    async def test_my_module():
        harness = ModuleTestHarness()

        # Register a test file
        harness.register_file(
            object_id="test-uuid",
            local_path="/path/to/test/file",
            file_enriched=FileEnrichedFactory.create_pe_file(object_id="test-uuid")
        )

        # Create and test module
        async with harness.create_module(MyModule) as module:
            should_run = await module.should_process("test-uuid")
            assert should_run

            result = await module.process("test-uuid")
            assert result is not None
"""

from .factories import FileEnrichedFactory
from .harness import ModuleTestHarness
from .mock_pool import MockAsyncpgPool
from .mock_storage import MockStorageMinio

__all__ = [
    "ModuleTestHarness",
    "FileEnrichedFactory",
    "MockStorageMinio",
    "MockAsyncpgPool",
]
