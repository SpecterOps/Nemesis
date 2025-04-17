FROM python:3.10.5-alpine3.15

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY sync.py .

CMD ["python", "-u", "sync.py"]
