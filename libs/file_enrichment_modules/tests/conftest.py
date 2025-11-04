import os
import warnings

# Ensure dev mode is enabled (catches many other bugs)
os.environ["PYTHONDEVMODE"] = "1"


# Configure warnings
def pytest_configure(config):
    # At a minimum, we should always report resource warnings
    # warnings.simplefilter("error", ResourceWarning)
    warnings.simplefilter("error")
