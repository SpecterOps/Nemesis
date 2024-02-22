# Goal

The goal of Nemesis is to create an extensible data-processing system for
Advesary Simulation operations which takes data collected from C2 agents and
provides efficiencies to operator workflows

Nemesis should be designed with a small core that wrangles data from various C2
platforms and outputs it to a system for data consumers to use. Examples of data
consumers are:

- ELK
- File text extraction and storage
- Sending discovered hashes to a hash cracker
- Vulnerability discovery pipeline for binaries
- etc.


## Project Structure

- **./cmd/** - contains the custom applications deployed on each container
- **./dockerfiles/** - contains Dockerfiles for building each container
- **./docs/** - documentation
- **./kubernetes/** - the k8s deployment/service configs for each pod/service
- **./packages/** - the protobuf definitions + Go/Python compiled protobufs, and common Python library functions
- **./skaffold.yaml** - the main skaffold deployment file


## Design Choices

Likely, all of these assumptions and justifications are wrong. As we learn more
about the requirements and the technologies used, we can correct the assumptions
and justifications while also holding off picking up a new technology because
it's shiny.

### HTTP Endpoint

Easy for people to create consumers without needing to structure their messages
with protobuf.

### ODR

The data that can be input into Nemesis is strictly defined in the [Operational Data
Reference (ODR)](#odr/README.md).

#### ODR Protobuf

Since the goal of this project is data processing, there should be a schema of
the data types available. Protobuf is a great solution to schema design because
strongly typed schemas can be generated for any language from the protobuf
specification. Consumers can then use protobuf to generate their client code and
have an accurate representation of the schema instead of reading data
dictionaries and hopefully writing their client code to specification.

The protobuf definitions for this project are in `./packages/protobufs/`, with a
compiled Python package in `./packages/python/nemesispb`. The protobuf can be
compiled with `./scripts/build_protobufs.sh`

### RabbitMQ

RabbitMQ has now replaced Kafka as the main queuing system for Nemesis. While
RabbitMQ does not have some of the features of Kafka such as persistent storage
and replay, it is significantly lighter weight and can still scale well.
