#!/usr/bin/env bash

# Load environment variables from the .env file
source /app/.env

# Configure Bitwarden with the provided API URL
bw config server "$API_URL"

# Authenticate with Bitwarden
STATUS="$(bw status | jq -r '.status')"
if [[ "$STATUS" == "unauthenticated" ]]; then
  echo "Authenticating with Bitwarden..."
  bw login --apikey --apikey "$ACCESS_TOKEN"
fi

# Unlock the vault if configured to do so
if [[ "$UNLOCK_VAULT" == "true" ]]; then
  echo "Unlocking the vault..."
  export BW_SESSION=$(bw unlock --passwordenv "$BW_PASSWORD" --raw)
  echo "Vault unlocked!"
fi

# Create the cron log file if it doesn't already exist
touch /var/log/cron.log

# Set up and run cron
CRON_SCHEDULE="${CRON_SCHEDULE:-0 1 * * *}"  
echo "$CRON_SCHEDULE /app/venv/bin/python /app/app/main.py >> /var/log/cron.log 2>&1" > /etc/cron.d/lazywarden-cron
chmod 0644 /etc/cron.d/lazywarden-cron
crontab /etc/cron.d/lazywarden-cron
service cron start

# Run the backup script initially to verify it works
/app/venv/bin/python /app/app/main.py

# Keep the container running by displaying the cron logs
tail -f /var/log/cron.log
