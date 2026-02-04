"""Main test harness for enrichment module testing."""

import os
from contextlib import asynccontextmanager
from typing import Any, TypeVar
from unittest.mock import patch

from .factories import FileEnrichedFactory
from .mock_pool import MockAsyncpgPool
from .mock_storage import MockStorageMinio

T = TypeVar("T")


class ModuleTestHarness:
    """Test harness for standalone enrichment module testing.

    Provides a coordinated environment for testing enrichment modules
    without requiring the full Nemesis infrastructure (Minio, PostgreSQL, Dapr).

    Usage:
        harness = ModuleTestHarness()

        # Register a test file with its metadata
        harness.register_file(
            object_id="test-uuid",
            local_path="/path/to/test/file.exe",
            file_enriched=FileEnrichedFactory.create_pe_file(object_id="test-uuid")
        )

        # Create and test the module
        async with harness.create_module(PEAnalyzer) as module:
            # Test should_process
            should_run = await module.should_process("test-uuid")
            assert should_run

            # Test process
            result = await module.process("test-uuid")
            assert result is not None
            assert result.module_name == "pe_analyzer"

        # Check what files were uploaded (transforms)
        uploaded = harness.get_uploaded_files()
    """

    def __init__(self):
        """Initialize the test harness."""
        self.storage = MockStorageMinio()
        self.pool = MockAsyncpgPool()
        self._patches: list = []

    def register_file(
        self,
        object_id: str,
        local_path: str,
        file_enriched: dict[str, Any] | None = None,
    ) -> None:
        """Register a test file with optional metadata.

        Args:
            object_id: UUID for the file
            local_path: Path to the actual file on disk
            file_enriched: Optional dict of file_enriched data. If not provided,
                          creates basic data from the file.
        """
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Test file not found: {local_path}")

        # Register with mock storage
        self.storage.register_file(object_id, local_path)

        # Create or use provided file_enriched data
        if file_enriched is None:
            file_name = os.path.basename(local_path)
            file_size = os.path.getsize(local_path)
            file_enriched = FileEnrichedFactory.create(
                object_id=object_id,
                file_name=file_name,
                size=file_size,
            )
        else:
            # Ensure object_id matches
            file_enriched["object_id"] = object_id

        # Register with mock pool
        self.pool.register_file_enriched(object_id, file_enriched)

    def register_file_bytes(
        self,
        object_id: str,
        data: bytes,
        file_enriched: dict[str, Any],
    ) -> None:
        """Register test data as bytes with metadata.

        Args:
            object_id: UUID for the file
            data: Raw bytes of the file
            file_enriched: Dict of file_enriched data
        """
        # Store bytes in mock storage's uploaded files dict
        self.storage._uploaded_files[object_id] = data

        # Ensure object_id matches
        file_enriched["object_id"] = object_id

        # Register with mock pool
        self.pool.register_file_enriched(object_id, file_enriched)

    @asynccontextmanager
    async def create_module(self, module_class: type[T]) -> T:
        """Create a module instance with mocked dependencies.

        This context manager patches StorageMinio and injects the mock pool,
        then yields the configured module instance.

        Args:
            module_class: The enrichment module class to instantiate

        Yields:
            Configured module instance with mocked dependencies

        Example:
            async with harness.create_module(PEAnalyzer) as module:
                result = await module.process("test-uuid")
        """
        # We need to patch StorageMinio in multiple places:
        # 1. The common.storage module (where it's defined)
        # 2. The specific module's namespace (where it's imported)

        # Get the module that contains the class
        module_name = module_class.__module__

        patches_to_apply = [
            # Patch at the definition site
            patch("common.storage.StorageMinio", return_value=self.storage),
        ]

        # Also patch at the import site if the module imported StorageMinio
        try:
            patches_to_apply.append(patch(f"{module_name}.StorageMinio", return_value=self.storage))
        except Exception:
            pass  # Module might not have imported StorageMinio directly

        # Start all patches
        for p in patches_to_apply:
            try:
                p.start()
                self._patches.append(p)
            except Exception:
                pass  # Ignore patch failures for modules that don't import StorageMinio

        try:
            # Create the module instance
            # The module's __init__ will get our mock storage
            if hasattr(module_class, "create_enrichment_module"):
                # Module uses factory function
                module = module_class.create_enrichment_module()
            else:
                # Module is instantiated directly
                module = module_class()

            # Replace storage with our mock (in case the module created its own)
            if hasattr(module, "storage"):
                module.storage = self.storage

            # Inject the mock pool
            if hasattr(module, "asyncpg_pool"):
                module.asyncpg_pool = self.pool

            yield module

        finally:
            # Stop all patches
            for p in self._patches:
                try:
                    p.stop()
                except Exception:
                    pass
            self._patches.clear()

    def get_uploaded_files(self) -> dict[str, bytes]:
        """Get files uploaded during testing (for assertions on transforms).

        Returns:
            Dict mapping object_id to bytes for in-memory uploads
        """
        return self.storage.get_uploaded_files()

    def get_uploaded_paths(self) -> dict[str, str]:
        """Get file paths uploaded during testing.

        Returns:
            Dict mapping object_id to original file path
        """
        return self.storage.get_uploaded_paths()

    def get_execute_log(self) -> list[tuple[str, tuple]]:
        """Get the log of executed database queries.

        Returns:
            List of (query, args) tuples
        """
        return self.pool.get_execute_log()

    def clear(self) -> None:
        """Clear all registered data, uploads, and logs."""
        self.storage.clear()
        self.pool.clear()

    def create_module_sync(self, module_class: type[T]) -> T:
        """Create a module instance synchronously (for simple setup).

        Use this when you need to set up a module outside of an async context,
        but remember to still use the async context manager for actual testing.

        Args:
            module_class: The enrichment module class to instantiate

        Returns:
            Configured module instance (not yet patched - use create_module for testing)

        Note:
            This method does NOT apply patches. Use create_module() for actual testing.
        """
        if hasattr(module_class, "create_enrichment_module"):
            module = module_class.create_enrichment_module()
        else:
            module = module_class()

        if hasattr(module, "storage"):
            module.storage = self.storage
        if hasattr(module, "asyncpg_pool"):
            module.asyncpg_pool = self.pool

        return module


async def run_module_test(
    module_class: type,
    test_file_path: str,
    file_enriched: dict[str, Any] | None = None,
    object_id: str = "test-object-id",
) -> tuple[bool, Any]:
    """Convenience function to quickly test a module against a file.

    Args:
        module_class: The enrichment module class to test
        test_file_path: Path to the test file
        file_enriched: Optional file_enriched metadata
        object_id: Object ID to use for the test

    Returns:
        Tuple of (should_process result, process result)

    Example:
        should_run, result = await run_module_test(
            PEAnalyzer,
            "/path/to/test.exe",
            FileEnrichedFactory.create_pe_file()
        )
    """
    harness = ModuleTestHarness()
    harness.register_file(object_id, test_file_path, file_enriched)

    async with harness.create_module(module_class) as module:
        should_run = await module.should_process(object_id, test_file_path)
        result = None
        if should_run:
            result = await module.process(object_id, test_file_path)
        return should_run, result
