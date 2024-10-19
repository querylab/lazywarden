"""
secrets_manager.py

This module retrieves secrets from Bitwarden.
"""
import os
from bitwarden_client import get_secret
from imports import logging

def retrieve_secrets(bw_client):
    """
    Retrieves secrets from Bitwarden.

    Args:
        bw_client (BitwardenClient): Bitwarden client instance.

    Returns:
        dict: Dictionary of secrets.

    Raises:
        ValueError: If one or more secrets cannot be retrieved.
    """
    secret_ids = {
        "BW_URL": os.getenv("BW_URL"),
        "BW_USERNAME": os.getenv("BW_USERNAME"),
        "BW_PASSWORD": os.getenv("BW_PASSWORD"),
        "BW_TOTP_SECRET": os.getenv("BW_TOTP_SECRET"),
        "ENCRYPTION_PASSWORD": os.getenv("ENCRYPTION_PASSWORD"),
        "ZIP_PASSWORD": os.getenv("ZIP_PASSWORD"),
        "ZIP_ATTACHMENT_PASSWORD": os.getenv("ZIP_ATTACHMENT_PASSWORD"),
        "PCLOUD_USERNAME": os.getenv("PCLOUD_USERNAME"),
        "PCLOUD_PASSWORD": os.getenv("PCLOUD_PASSWORD"),
        "MEGA_EMAIL": os.getenv("MEGA_EMAIL"),
        "MEGA_PASSWORD": os.getenv("MEGA_PASSWORD"),
        "DROPBOX_ACCESS_TOKEN": os.getenv("DROPBOX_ACCESS_TOKEN"),
        "DROPBOX_REFRESH_TOKEN": os.getenv("DROPBOX_REFRESH_TOKEN"),
        "DROPBOX_APP_KEY": os.getenv("DROPBOX_APP_KEY"),
        "DROPBOX_APP_SECRET": os.getenv("DROPBOX_APP_SECRET"),
        "TODOIST_TOKEN": os.getenv("TODOIST_TOKEN"),
        "CALDAV_URL": os.getenv("CALDAV_URL"),
        "CALDAV_USERNAME": os.getenv("CALDAV_USERNAME"),
        "CALDAV_PASSWORD": os.getenv("CALDAV_PASSWORD"),
        "NEXTCLOUD_URL": os.getenv("NEXTCLOUD_URL"),
        "NEXTCLOUD_USERNAME": os.getenv("NEXTCLOUD_USERNAME"),
        "NEXTCLOUD_PASSWORD": os.getenv("NEXTCLOUD_PASSWORD"),
        "SEAFILE_SERVER_URL": os.getenv("SEAFILE_SERVER_URL"),
        "SEAFILE_USERNAME": os.getenv("SEAFILE_USERNAME"),
        "SEAFILE_PASSWORD": os.getenv("SEAFILE_PASSWORD"),
        "FILEBASE_ACCESS_KEY": os.getenv("FILEBASE_ACCESS_KEY"),
        "FILEBASE_SECRET_KEY": os.getenv("FILEBASE_SECRET_KEY"),
        "KEEPASS_PASSWORD": os.getenv("KEEPASS_PASSWORD"),
        "STORJ_ACCESS_KEY": os.getenv("STORJ_ACCESS_KEY"),
        "STORJ_SECRET_KEY": os.getenv("STORJ_SECRET_KEY"),
        "STORJ_ENDPOINT": os.getenv("STORJ_ENDPOINT"),
        "R2_ACCESS_KEY_ID": os.getenv("R2_ACCESS_KEY_ID"),
        "R2_SECRET_ACCESS_KEY": os.getenv("R2_SECRET_ACCESS_KEY"),
        "R2_ENDPOINT_URL": os.getenv("R2_ENDPOINT_URL"),
        "VIKUNJA_API_TOKEN": os.getenv("VIKUNJA_API_TOKEN"),
        "VIKUNJA_URL": os.getenv("VIKUNJA_URL")
    }

    secrets = {}
    for key, secret_id in secret_ids.items():
        if secret_id is None:
            raise ValueError(f"Secret {key} could not be retrieved from environment variables")
        secrets[key] = get_secret(bw_client, secret_id)

    return secrets
