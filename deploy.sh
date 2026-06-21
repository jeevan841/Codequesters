#!/bin/bash
# deploy.sh — Deploy Codequesters to Google Cloud Run
#
# Prerequisites:
#   1. gcloud auth login
#   2. gcloud config set project <your-project-id>
#   3. All required env vars exported (see .env.example)
#
# Usage:
#   export PROJECT_ID=your-gcp-project-id
#   ./deploy.sh

set -euo pipefail

# ─── Config ───────────────────────────────────────────────────────────────────
SERVICE_NAME="hyd-voice-agent"
REGION="asia-south1"  # Mumbai — low latency for Hyderabad

PROJECT_ID="${PROJECT_ID:-}"
if [[ -z "$PROJECT_ID" ]]; then
  echo "Error: PROJECT_ID environment variable is not set."
  echo "Usage: PROJECT_ID=your-gcp-project-id ./deploy.sh"
  exit 1
fi

# ─── Required env vars to pass to Cloud Run ───────────────────────────────────
required_vars=(DATABASE_URL SESSION_SECRET ALLOWED_ORIGINS GROQ_API_KEY
               GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET
               GITHUB_CLIENT_ID GITHUB_CLIENT_SECRET
               EXOTEL_SID EXOTEL_API_KEY EXOTEL_API_TOKEN EXOTEL_VIRTUAL_NUMBER
               MY_PHONE)

env_flags=""
for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "Warning: $var is not set — the app will fail to start if it is required."
  else
    env_flags="$env_flags,$var=${!var}"
  fi
done
# Trim leading comma
env_flags="${env_flags#,}"

# ─── 1. Build and push container ──────────────────────────────────────────────
echo "Building container image..."
gcloud builds submit --tag "gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

# ─── 2. Deploy to Cloud Run ───────────────────────────────────────────────────
echo "Deploying to Cloud Run (region: ${REGION})..."
gcloud run deploy "${SERVICE_NAME}" \
  --image "gcr.io/${PROJECT_ID}/${SERVICE_NAME}" \
  --platform managed \
  --region "${REGION}" \
  --allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --set-env-vars "${env_flags}" \
  --port 8080

echo ""
echo "✅ Deployment complete."
echo "Service URL: $(gcloud run services describe ${SERVICE_NAME} --region ${REGION} --format 'value(status.url)')"