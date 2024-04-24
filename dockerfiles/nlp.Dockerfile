####################################
# OS dependencies
####################################
FROM python:3.11.2-bullseye AS dependencies-os


# install our necessary dependencies
# RUN apt-get update -y


############################################################
# Generic Python dependencies and configuration
############################################################
FROM dependencies-os AS python-build-tools

ARG ENVIRONMENT=dev

# Always write stdout immediately (don't buffer output)
ENV PYTHONUNBUFFERED=1  

ENV POETRY_HOME=/opt/poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true

# Install Poetry and add it to the path
RUN pip install poetry==1.8.2


####################################
# Container specific dependencies
####################################
FROM python-build-tools AS build

WORKDIR /app/cmd/nlp


# HACK: Pre-download the embedding model(s) we're using so we don't have to wait for it to download on first use 
# Models are in ascending order of size, descending order of processing speed. 
# Installing the packages with poetry so we don't have to re-download them again later
# NOTE: The .venv directory is not deleted after this, and later re-used 

RUN poetry init --quiet \
&& poetry add langchain-community sentence-transformers \
&& poetry install \
&& poetry run python -c "from langchain_community.embeddings import HuggingFaceEmbeddings; \
embeddings = [HuggingFaceEmbeddings(model_name=model) for model in \
['TaylorAI/bge-micro-v2', 'Harmj0y/nemesis-gte-tiny', 'TaylorAI/gte-tiny', 'thenlper/gte-small']]" \
&& rm pyproject.toml poetry.lock



# Rebuild the poetry environment if the package dependencies change (stored in pyproject.toml/poetry.lock)
COPY cmd/nlp/poetry.lock cmd/nlp/pyproject.toml ./

# copy local libraries
COPY packages/python/nemesispb/ /app/packages/python/nemesispb/
COPY packages/python/nemesiscommon/ /app/packages/python/nemesiscommon/

# RUN poetry install $(if [ "${ENVIRONMENT}" = 'production' ]; then echo "--without dev"; fi;) --no-root --no-interaction --no-ansi -vvv


# # ####################################
# # # Runtime
# # ####################################
# # FROM build AS runtime
# # ENV PATH="/app/cmd/nlp/.venv/bin:$PATH"

# # # copy in the main nlp container code
# COPY cmd/nlp/nlp/ ./nlp/

# # for the semantic search api
# EXPOSE 9803

# CMD ["python3", "-m", "nlp"]
