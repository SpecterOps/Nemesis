# This is the production image used as a base for **all** python projects
# It is a slim image with only python installed
# Only make modifications if you are sure it is needed for **all** python projects
FROM python:3.13.2-slim

# Set environment variables for production use

# Don't buffer output so container orchestrators can get logs in real-time
ENV PYTHONUNBUFFERED=1 \
    # Keeps pip from caching downloaded packages
    PIP_NO_CACHE_DIR=1 \
    # Prevents pip from checking for newer versions online
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Logging level for the application
    LOG_LEVEL=INFO



# Make sure this stays as one command so the layer doesn't explode
# Also, ensure the clean + delete happens to remove unnecessary files
# from the prod image (saves many MBs of space)
RUN apt-get update && \
    # Install wget for health checks
    apt-get install -y --no-install-recommends wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    # Create a non-root user
    adduser --disabled-password --gecos '' nemesis

WORKDIR /src
