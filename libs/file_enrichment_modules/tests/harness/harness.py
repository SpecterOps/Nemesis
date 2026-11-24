# pyright: reportAttributeAccessIssue=false, reportArgumentType=false, reportReturnType=false
"""Main test harness for enrichment module testing."""

import functools
import os
from contextlib import asynccontextmanager
from typing import Any, TypeVar
from unittest.mock import patch

from .factories import FileEnrichedFactory
from .ids import label_key, label_uuid
from .mock_pool import MockAsyncpgPool
from .mock_storage import MockStorageMinio

T = TypeVar("T")


def _with_uuid_object_id(method):
    """Wrap process/should_process so a test label passed as object_id reaches the module as its UUID."""

    @functools.wraps(method)
    async def wrapper(object_id, *args, **kwargs):
        return await method(label_uuid(object_id), *args, **kwargs)

    return wrapper


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

        object_id = label_uuid(object_id)

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
        object_id = label_uuid(object_id)

        # Store bytes in mock storage's uploaded files dict
        self.storage._uploaded_files[label_key(object_id)] = data

        # Ensure object_id matches
        file_enriched["object_id"] = object_id

        # Register with mock pool
        self.pool.register_file_enriched(object_id, file_enriched)

    def _start_storage_patches(self, module_class: type) -> list:
        """Patch StorageMinio so module construction never touches Dapr/SeaweedFS.

        StorageMinio is patched both at its definition site (common.storage) and at
        the import site in the module under test, if the module imported it directly.

        Returns:
            The started patchers; the caller is responsible for stopping them.
        """
        targets = ["common.storage.StorageMinio", f"{module_class.__module__}.StorageMinio"]
        started = []
        for target in targets:
            p = patch(target, return_value=self.storage)
            try:
                p.start()
            except AttributeError:
                continue  # Module didn't import StorageMinio directly
            started.append(p)
        return started

    def _instantiate(self, module_class: type[T]) -> T:
        """Instantiate a module and inject the mock storage and pool."""
        if hasattr(module_class, "create_enrichment_module"):
            module = module_class.create_enrichment_module()
        else:
            module = module_class()

        # Tests address files by readable labels; the module only ever receives UUIDs
        for name in ("process", "should_process"):
            method = getattr(module, name, None)
            if method is not None:
                setattr(module, name, _with_uuid_object_id(method))

        # Replace storage with our mock (in case the module created its own)
        if hasattr(module, "storage"):
            module.storage = self.storage
        if hasattr(module, "asyncpg_pool"):
            module.asyncpg_pool = self.pool

        return module

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
        patches = self._start_storage_patches(module_class)
        try:
            module = self._instantiate(module_class)
            yield module
        finally:
            for p in patches:
                try:
                    p.stop()
                except Exception:
                    pass

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
            Configured module instance with mock storage and pool injected

        Note:
            StorageMinio is only patched while the module is constructed. Code that
            instantiates StorageMinio later (e.g. inside process()) is not covered;
            use create_module() for those tests.
        """
        patches = self._start_storage_patches(module_class)
        try:
            return self._instantiate(module_class)
        finally:
            for p in patches:
                p.stop()


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
