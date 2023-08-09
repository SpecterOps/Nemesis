FROM python:3.10.5-alpine3.15

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

WORKDIR /app
COPY sliver_service /app/sliver_service

CMD ["python", "-m", "sliver_service"]
