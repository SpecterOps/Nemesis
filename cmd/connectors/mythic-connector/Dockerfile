FROM python:3.13.0b1-slim

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY sync.py .

CMD python -u sync.py
