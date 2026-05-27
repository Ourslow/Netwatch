FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY beacon_detect.py .

CMD ["python", "beacon_detect.py"]
