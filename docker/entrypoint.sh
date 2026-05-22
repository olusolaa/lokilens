#!/bin/sh
# If a GCP service account key is provided via env var, write it to a file
# so the Google SDK picks it up via GOOGLE_APPLICATION_CREDENTIALS.
if [ -n "$GCP_SERVICE_ACCOUNT_KEY" ]; then
  echo "$GCP_SERVICE_ACCOUNT_KEY" > /tmp/gcp-key.json
  export GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp-key.json
fi

exec /lokilens-mcp
