FROM jupyter/datascience-notebook:latest

# RUN pip install kafka-python

WORKDIR /home/jovyan/
RUN mv work examples
COPY cmd/jupyter/post_data.ipynb /home/jovyan/examples
COPY packages/protobufs/nemesis.proto /home/jovyan/examples
COPY sample_files/ examples/sample_files