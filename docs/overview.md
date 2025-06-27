# Overview

The goal of Nemesis is to create an extensible file-processing system for
Advesary Simulation operations which takes files collected from C2 agents and
provides automated analysis and assists with triage.

## Project Structure

- **./docs/** - documentation that's published to the GitHub page
- **./infra/** - infrastructure files (Dapr, Postgres, etc.)
- **./libs/** - common library files and the file_enrichment_modules
- **./projects/** - the main logic files that comprise the various services
- **./tools/** - misc helper scripts

## Design Choices

Many of the decisions made with Nemesis 1.X resulted in an over-engineered system that was less flexible and difficult to expand/maintain. Nemesis 2.0 aims to take lessons learned and simplifies the entire architecture:

- Docker/Docker-Compose is used instead of k8s for speed of development
and general ease of use, especially as we didn't experiment with scaling in the
previous version (we may move back to k8s at some point).
- Dapr is now used to increase reliability and to offload infrastructure plumbing concerns
- Strict protobuf schemas were dropped in favor of a flexibilbe schema
- Overall project code/approaches were greatly simplified
- Dropped Elasticsearch (the largest resource hog) in favor of consolidating with PostgreSQL

### HTTP Endpoint

Easy for people to create consumers without needing to structure their messages
with protobuf.

### RabbitMQ

We still use RabbitMQ as the main queuing system for Nemesis. While
RabbitMQ does not have some of the features of Kafka such as persistent storage
and replay, it is significantly lighter weight and can still scale well.

With Dapr pub/sub integration, this can easily be swapped out.