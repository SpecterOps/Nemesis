FROM python:3.13.0b1-slim

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

WORKDIR /app
COPY sliver_service /app/sliver_service

CMD ["python", "-m", "sliver_service"]
