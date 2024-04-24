##########################################################
# JTR base image used in enrichment and passwordcracker
# Published to specterops/nemesis-jtr-base
##########################################################
FROM python:3.11.2-slim-bullseye as dependencies

# install our necessary dependencies
RUN apt-get update -y && apt-get install -y wamerican libcompress-raw-lzma-perl build-essential wget


FROM dependencies AS build
# clone and build a specific commit for JTR
#   Commit date - Feb 2, 2024
ENV JTR_COMMIT f55f42067431c0e8f67e600768cd8a3ad8439818
RUN wget https://github.com/openwall/john/tarball/f55f42067431c0e8f67e600768cd8a3ad8439818 -O john.tar.gz && tar -xzf john.tar.gz && rm john.tar.gz && mv *john* /opt/john 
RUN apt-get install -y libssl-dev
RUN cd /opt/john/src && ./configure && make


##########################################################
# Runtime - Discard all the build tools installed in the old stage and only keep the built JTR
##########################################################
FROM python:3.11.2-slim-bullseye as runtime
COPY --from=build /opt/john /opt/john

RUN apt-get update && apt-get install -y libgomp1
