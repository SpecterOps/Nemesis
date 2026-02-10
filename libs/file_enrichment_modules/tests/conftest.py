import os
import warnings

import pytest

# Ensure dev mode is enabled (catches many other bugs)
os.environ["PYTHONDEVMODE"] = "1"


# Configure warnings
def pytest_configure(config):
    # At a minimum, we should always report resource warnings
    # warnings.simplefilter("error", ResourceWarning)
    warnings.simplefilter("error")


# Re-export harness fixtures for convenience
@pytest.fixture
def test_harness():
    """Provide a fresh ModuleTestHarness for each test."""
    from tests.harness import ModuleTestHarness

    harness = ModuleTestHarness()
    yield harness
    harness.clear()


@pytest.fixture
def mock_storage():
    """Provide a fresh MockStorageMinio for each test."""
    from tests.harness import MockStorageMinio

    storage = MockStorageMinio()
    yield storage
    storage.clear()


@pytest.fixture
def mock_pool():
    """Provide a fresh MockAsyncpgPool for each test."""
    from tests.harness import MockAsyncpgPool

    pool = MockAsyncpgPool()
    yield pool
    pool.clear()
