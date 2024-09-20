FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

# Set the working directory inside the container
WORKDIR /usr/local/bin

# Update the package list and install necessary dependencies: curl, unzip, libsecret, jq, Python3, pip, virtualenv, and cron
RUN apt update && apt install -y curl unzip libsecret-1-0 jq python3 python3-pip python3-venv cron

# Copy the entrypoint script into the container
COPY entrypoint.sh .

# Fetch the latest Bitwarden CLI version and install it
RUN export VER=$(curl -H "Accept: application/vnd.github+json" https://api.github.com/repos/bitwarden/clients/releases | jq -r 'sort_by(.published_at) | reverse | .[].name | select(index("CLI"))' | sed 's:.*CLI v::' | head -n 1) && \
  curl -LO "https://github.com/bitwarden/clients/releases/download/cli-v${VER}/bw-linux-${VER}.zip" \
  && unzip *.zip && chmod +x ./bw

# Copy the necessary files into the container
COPY requirements.txt /app/requirements.txt
COPY .env /app/.env
COPY config/bitwarden-drive-backup-google.json /root/lazywarden/config/bitwarden-drive-backup-google.json

# Copy the application files to the container
COPY app/ /app/app/

# Create a virtual environment and install Python dependencies
RUN python3 -m venv /app/venv
RUN /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Ensure the entrypoint script has execution permissions
RUN chmod +x /usr/local/bin/entrypoint.sh

# Define the entrypoint to run the entrypoint.sh script when the container starts
ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]
