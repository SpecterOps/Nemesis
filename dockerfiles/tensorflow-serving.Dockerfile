FROM tensorflow/serving:2.8.2 AS tensorflowcommon

COPY cmd/tensorflow-serving/models/ /models/

# gRPC port
EXPOSE 8500
# REST API port
EXPOSE 8501

CMD ["--model_config_file=/models/models.config"]
