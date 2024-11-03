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
    """
   
    required_secrets = [
        "BW_URL", "BW_USERNAME", "BW_PASSWORD", "ENCRYPTION_PASSWORD",
        "ZIP_PASSWORD", "ZIP_ATTACHMENT_PASSWORD"
    ]
    
    optional_secrets = [
        "PCLOUD_USERNAME", "PCLOUD_PASSWORD", "MEGA_EMAIL", "MEGA_PASSWORD", "DROPBOX_ACCESS_TOKEN",
        "DROPBOX_REFRESH_TOKEN", "DROPBOX_APP_KEY", "DROPBOX_APP_SECRET", "TODOIST_TOKEN",
        "CALDAV_URL", "CALDAV_USERNAME", "CALDAV_PASSWORD", "NEXTCLOUD_URL",
        "NEXTCLOUD_USERNAME", "NEXTCLOUD_PASSWORD", "SEAFILE_SERVER_URL",
        "SEAFILE_USERNAME", "SEAFILE_PASSWORD", "FILEBASE_ACCESS_KEY", "FILEBASE_SECRET_KEY",
        "KEEPASS_PASSWORD", "STORJ_ACCESS_KEY", "STORJ_SECRET_KEY", "STORJ_ENDPOINT",
        "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_ENDPOINT_URL",
        "VIKUNJA_API_TOKEN", "VIKUNJA_URL", "B2_APP_KEY_ID", "B2_APP_KEY","BW_TOTP_SECRET"
    ]

    secrets = {}

  
    for secret_name in required_secrets:
        secret_id = os.getenv(secret_name)
        if not secret_id:
            logging.error(f"Required secret '{secret_name}' is missing from environment variables.")
            raise ValueError(f"Required secret '{secret_name}' is missing.")
        try:
            secrets[secret_name] = get_secret(bw_client, secret_id)
        except Exception as e:
            logging.error(f"Failed to retrieve required secret '{secret_name}': {e}")
            raise ValueError(f"Error retrieving required secret '{secret_name}'")

   
    for secret_name in optional_secrets:
        secret_id = os.getenv(secret_name)
        if not secret_id:
            logging.warning(f"Optional secret '{secret_name}' is not set. Some functionality may be disabled.")
            continue
        
        try:
            secrets[secret_name] = get_secret(bw_client, secret_id)
        except Exception as e:
          
            logging.warning(f"Could not retrieve optional secret '{secret_name}' (ID: {secret_id}): {e}")

    return secrets
