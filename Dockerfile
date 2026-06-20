FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .

# Install system dependencies for audio processing if needed later
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port and run using Uvicorn
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]