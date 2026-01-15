FROM quay.io/jupyter/scipy-notebook:python-3.13

USER root

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Switch back to jovyan user
USER jovyan

# Install Python packages for Hasura interaction and data analysis
RUN pip install --no-cache-dir \
    gql[requests]==3.5.3 \
    requests==2.32.3 \
    psycopg2-binary==2.9.10 \
    pandas==2.3.0 \
    matplotlib==3.10.3 \
    seaborn==0.13.2 \
    plotly==6.1.2 \
    ipywidgets==8.1.7 \
    python-dotenv==1.1.0

# Create working directory
WORKDIR /home/jovyan/work

# Copy startup script
COPY --chown=jovyan:users jupyter_config.py /home/jovyan/.jupyter/

# Copy notebooks
COPY --chown=jovyan:users notebooks/ /home/jovyan/work/

# Expose port
EXPOSE 8888

# Start JupyterLab
CMD ["start-notebook.py", "--config=/home/jovyan/.jupyter/jupyter_config.py"]