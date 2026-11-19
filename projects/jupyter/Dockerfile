# Pinned release: JupyterLab 4.6.6, Notebook 7.6.5, Python 3.13.18, Ubuntu 26.04
FROM quay.io/jupyter/scipy-notebook:2026-11-16

USER root

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Switch back to jovyan user
USER jovyan

# Install Python packages for Hasura interaction and data analysis.
# pandas, matplotlib, seaborn, ipywidgets and requests come from the base image;
# don't re-pin them here or pip downgrades the image's newer versions.
RUN pip install --no-cache-dir \
    gql[requests]==4.4.0 \
    "graphql-core>=3.2.12" \
    psycopg2-binary==2.9.13 \
    plotly==7.1.0 \
    python-dotenv==1.2.4

# Share the dependency-free logging helper without installing the service libraries.
COPY --chown=jovyan:users ./libs/common/common/log_safety.py /opt/nemesis/common/log_safety.py
ENV PYTHONPATH=/opt/nemesis

# Create working directory
WORKDIR /home/jovyan/work

# Copy startup script
COPY --chown=jovyan:users ./projects/jupyter/jupyter_config.py /home/jovyan/.jupyter/

# Copy notebooks
COPY --chown=jovyan:users ./projects/jupyter/notebooks/ /home/jovyan/work/

# Expose port
EXPOSE 8888

# Start JupyterLab
CMD ["start-notebook.py", "--config=/home/jovyan/.jupyter/jupyter_config.py"]
