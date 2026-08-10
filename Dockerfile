# AEGIS SAAS CLOUD PLATFORM - DOCKERFILE v7.0
# Author: Eduardo Mexquitic Rodriguez (EMR)
# Force Cache Invalidation: 2026-08-10-00:03

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV FLASK_APP=app.py

CMD ["python", "app.py"]
