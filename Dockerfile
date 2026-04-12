FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .

# Install system dependencies for audio processing if needed later
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port and run using Gunicorn with WebSocket worker
EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "app:app"]