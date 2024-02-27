##########################################################
# JTR base image used in enrichment and passwordcracker
# Published to harmj0y/jtr-base
##########################################################
FROM python:3.11.2-bullseye as dependencies
ENV PYTHONUNBUFFERED=true

# install our necessary dependencies
RUN apt-get update -y && apt-get install yara -y && apt-get install git -y && apt-get install wamerican -y && apt-get install libcompress-raw-lzma-perl -y

# clone and build a specific commit for JTR
#   Commit date - Feb 2, 2024
ENV JTR_COMMIT f55f42067431c0e8f67e600768cd8a3ad8439818
RUN cd /opt/ && git clone https://github.com/openwall/john && cd john && git checkout ${JTR_COMMIT} && cd ./src && ./configure && make

# any additional deps so we don't have to compile John again
RUN apt-get install unzip
