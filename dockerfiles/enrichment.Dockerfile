####################################
# Pre-built python:3.11.2-bullseye base w/ JTR
####################################
FROM harmj0y/jtr-base AS dependencies-os
WORKDIR /app/cmd/enrichment

# first we have to pip3 install this *normally* so the _fastpbkdf2.abi3.so properly builds (because Poetry no like)
RUN pip3 install msfastpbkdf2


####################################
# Python dependencies
####################################
FROM dependencies-os AS dependencies-python

ARG ENVIRONMENT=dev
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
ENV PATH="$POETRY_HOME/bin:$PATH"

# install Poetry
RUN python3 -c 'from urllib.request import urlopen; print(urlopen("https://install.python-poetry.org").read().decode())' | python3 -


####################################
# Container specific dependencies
####################################
FROM dependencies-python AS build

# clone the common yara rulebase
# commit 2a8de15d3c2fb95c1e261edfe3f4154480b93161 - Jan 11, 2023
#   we have to tag this to a comment because ~sometimes~ (often) invalid rules sneak in
#   License: Detection Rule License (DRL) 1.1 - https://github.com/Neo23x0/signature-base/blob/master/LICENSE
RUN git clone https://github.com/Neo23x0/signature-base /app/cmd/enrichment/enrichment/lib/public_yara/signature-base/ && cd /app/cmd/enrichment/enrichment/lib/public_yara/signature-base/ && git checkout 2a8de15d3c2fb95c1e261edfe3f4154480b93161
# the following use external variables and have to be removed
#   ref- https:/github.com/Neo23x0/signature-base#external-variables-in-yara-rules
RUN rm /app/cmd/enrichment/enrichment/lib/public_yara/signature-base/yara/generic_anomalies.yar
RUN rm /app/cmd/enrichment/enrichment/lib/public_yara/signature-base/yara/general_cloaking.yar
RUN rm /app/cmd/enrichment/enrichment/lib/public_yara/signature-base/yara/gen_webshells_ext_vars.yar
RUN rm /app/cmd/enrichment/enrichment/lib/public_yara/signature-base/yara/thor_inverse_matches.yar
RUN rm /app/cmd/enrichment/enrichment/lib/public_yara/signature-base/yara/yara_mixed_ext_vars.yar
RUN rm /app/cmd/enrichment/enrichment/lib/public_yara/signature-base/yara/configured_vulns_ext_vars.yar
RUN rm /app/cmd/enrichment/enrichment/lib/public_yara/signature-base/yara/*_ext_vars* 2> /dev/null || true


COPY cmd/enrichment/poetry.lock cmd/enrichment/pyproject.toml ./

# copy local libraries
COPY packages/python/nemesispb/ /app/packages/python/nemesispb/
COPY packages/python/nemesiscommon/ /app/packages/python/nemesiscommon/

# use Poetry to install the local packages
RUN poetry install $(if [ "${ENVIRONMENT}" = 'production' ]; then echo "--without dev"; fi;) --no-root --no-interaction --no-ansi -vvv

# this is a stupid exception - becuase the _fastpbkdf2.abi3.so isn't compiled correctly with Poetry so we have to copy it in from the *normal* build location
RUN poetry run pip3 install msfastpbkdf2
RUN cp /usr/local/lib/python3.11/site-packages/msfastpbkdf2/_fastpbkdf2.abi3.so /app/cmd/enrichment/.venv/lib/python3.11/site-packages/msfastpbkdf2/_fastpbkdf2.abi3.so

# the main enrichment container code
COPY cmd/enrichment/enrichment/ ./enrichment/



####################################
# Runtime
####################################
# FROM build AS runtime
ENV PATH="/app/cmd/enrichment/.venv/bin:$PATH"

# for generate_crack_list
EXPOSE 9900
# for the yara api
EXPOSE 9700
# for the web-api
EXPOSE 9910

CMD ["python3", "-m", "watchdog.watchmedo", "auto-restart", "--pattern", "*.py", "--recursive", "--signal", "SIGKILL", "--", "python3", "-m", "enrichment"]
