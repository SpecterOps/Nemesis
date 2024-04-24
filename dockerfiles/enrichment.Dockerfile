####################################
# Pre-built python:3.11.2-bullseye base w/ JTR
####################################
FROM specterops/nemesis-jtr-base AS dependencies-os
WORKDIR /app/cmd/enrichment


############################################################
# Generic Python dependencies any python application needs
############################################################
FROM dependencies-os AS python-build-tools

ARG ENVIRONMENT=dev
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true

RUN pip install poetry==1.8.2

##################################################################
FROM python:3.11.2-slim-bullseye AS msfastpbkdf2

RUN apt-get update && apt-get -y install gcc libssl-dev

# first we have to pip3 install this *normally* so the _fastpbkdf2.abi3.so properly builds (because Poetry no like)
RUN pip3 install msfastpbkdf2

####################################
# Enrichment container specific dependencies
####################################
FROM python-build-tools AS enrichment-application

RUN apt-get update && apt-get install -y yara wget


# Clone our base Yara rules
#   License: Detection Rule License (DRL) 1.1 - https://github.com/Neo23x0/signature-base/blob/master/LICENSE
# Set a specific commit for the rule base in case someone changes the license
#   Commit date - March 2, 2024
RUN cd /tmp/ && wget "https://github.com/Neo23x0/signature-base/tarball/cd7651d2ccf4158a35a8d1cc0441928f7d92818f" -O signature-base.tar.gz && tar -xzf signature-base.tar.gz && rm signature-base.tar.gz && mv *signature-base* /app/cmd/enrichment/signature-base

# copy local libraries
COPY packages/python/nemesispb/ /app/packages/python/nemesispb/
COPY packages/python/nemesiscommon/ /app/packages/python/nemesiscommon/

COPY cmd/enrichment/poetry.lock cmd/enrichment/pyproject.toml ./

# use Poetry to install the local packages
RUN poetry install $(if [ "${ENVIRONMENT}" = 'production' ]; then echo "--without dev"; fi;) --no-root --no-interaction --no-ansi -vvv

# this is a stupid exception - becuase the _fastpbkdf2.abi3.so isn't compiled correctly with Poetry so we have to copy it in from the *normal* build location
RUN poetry run pip3 install msfastpbkdf2
COPY --from=msfastpbkdf2 /usr/local/lib/python3.11/site-packages/msfastpbkdf2/_fastpbkdf2.abi3.so /app/cmd/enrichment/.venv/lib/python3.11/site-packages/msfastpbkdf2/_fastpbkdf2.abi3.so

# the main enrichment container code
COPY cmd/enrichment/enrichment/ ./enrichment/

# Clean the rules to get rid of Thor-ness that throws Yara compilation errors
RUN poetry run python3 enrichment/lib/public_yara/clean_yara_rules.py


####################################
# Runtime
####################################
FROM enrichment-application AS runtime
ENV PATH="/app/cmd/enrichment/.venv/bin:$PATH"

# for generate_crack_list
EXPOSE 9900
# for the yara api
EXPOSE 9700
# for the web-api
EXPOSE 9910

CMD ["python3", "-m", "watchdog.watchmedo", "auto-restart", "--pattern", "*.py", "--recursive", "--signal", "SIGKILL", "--", "python3", "-m", "enrichment"]
