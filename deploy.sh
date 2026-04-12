#!/bin/bash
# Ensure you are authenticated with: gcloud auth login

PROJECT_ID="your-gcp-project-id"
SERVICE_NAME="hyd-voice-agent"
REGION="asia-south1" # Mumbai region for low latency to Hyderabad

# 1. Build and submit container
gcloud builds submit --tag gcr.io/$PROJECT_ID/$SERVICE_NAME

# 2. Deploy to Cloud Run (Free tier friendly e2-micro equivalent)
gcloud run deploy $SERVICE_NAME \
  --image gcr.io/$PROJECT_ID/$SERVICE_NAME \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --set-env-vars GEMINI_API_KEY="your_api_key" \
  --port 8080