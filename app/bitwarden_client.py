import logging
import shlex
import pyotp
import sys
import subprocess
import json
from bitwarden_sdk import BitwardenClient, DeviceType, client_settings_from_dict

def setup_bitwarden_client(api_url, identity_url):
    try:
        bw_client = BitwardenClient(
            client_settings_from_dict(
                {
                    "apiUrl": api_url,
                    "deviceType": DeviceType.SDK,
                    "identityUrl": identity_url,
                    "userAgent": "Python",
                }
            )
        )
        return bw_client
    except Exception as e:
        logging.error(f"Error setting up Bitwarden client: {e}")
        raise

def authenticate_bitwarden_client(bw_client, access_token):
    try:
       
        auth_client = bw_client.auth()
        auth_client.login_access_token(access_token)
        logging.info("Authenticated successfully using access token.")
    except Exception as e:
        logging.error(f"Error authenticating to Bitwarden: {e}")
        raise


def get_secret(bw_client, secret_id):
    from uuid import UUID
    try:
        UUID(secret_id, version=4)
        secret = bw_client.secrets().get(secret_id)
        return secret.data.value
    except Exception as e:
        logging.error(f"Error retrieving secret {secret_id}: {e}")
        raise

def check_logged_in(password):
    try:
        command = shlex.split(f"bw unlock --raw {password}")
        session_key_result = subprocess.run(command, capture_output=True, text=True)
        if session_key_result.returncode == 0:
            logging.info("User is already logged in and vault is unlocked.")
            return session_key_result.stdout.strip()
        else:
            logging.info("User is not logged in or vault is locked.")
            return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Error checking Bitwarden login status: {e.stderr}")
        return None

def is_vault_unlocked():
    try:
        command = shlex.split("bw sync")
        sync_result = subprocess.run(command, capture_output=True, text=True)
        if sync_result.returncode == 0:
            logging.info("Vault is unlocked.")
            return True
        else:
            logging.info("Vault is locked.")
            return False
    except subprocess.CalledProcessError as e:
        logging.error(f"Error checking vault unlock status: {e.stderr}")
        return False

def generate_totp(secret):
    if not secret:
        raise ValueError("TOTP secret is empty or not set.")
    
    secret = secret.replace(" ", "").strip()  
    try:
        totp = pyotp.TOTP(secret)
        totp_code = totp.now()
        logging.info(f"Generated TOTP code: {totp_code}")
        return totp_code
    except Exception as e:
        logging.error(f"Error generating TOTP code: {e}")
        raise

def unlock_vault(password):
    try:
        logging.info("Unlocking the Bitwarden vault.")
        command = shlex.split(f"bw unlock --raw {password}")
        session_key_result = subprocess.run(command, capture_output=True, text=True)
        if session_key_result.returncode == 0:
            logging.info("Vault unlocked successfully.")
            return session_key_result.stdout.strip()
        else:
            logging.error(f"Failed to unlock the vault. Output: {session_key_result.stderr}")
            return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Error unlocking the vault: {e.stderr}")
        return None
    

def login_bitwarden(username, password, totp_secret=None):
    session_key = check_logged_in(password)
    if session_key:
        return session_key

    try:
        command = ["bw", "login", "--nointeraction", username, password]
        
       
        if totp_secret:
            try:
                totp_code = generate_totp(totp_secret)
                command += ["--method", "0", "--code", totp_code]
            except Exception as e:
                logging.error(f"Error generating TOTP code: {e}")
                totp_code = None  

        logging.info(f"Execute login command: {(' '.join(command)).replace(password, '********')}")

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        logging.info(f"Login process stdout:\n{result.stdout}")
        logging.info(f"Login process stderr:\n{result.stderr}")
        output = result.stdout + result.stderr

        # Verifica si el inicio de sesión fue exitoso
        if "You are already logged in as" in output or "You are logged in!" in output:
            logging.info("Bitwarden login successful, attempting to unlock the vault.")
            session_key = unlock_vault(password)
            if session_key:
                return session_key
            else:
                raise Exception("Failed to unlock the vault after login.")
        else:
            logging.error(f"Bitwarden login failed:\n{output}")
            raise Exception("Failed to login to Bitwarden.")
    except Exception as e:
        logging.error(f"Error during Bitwarden login: {e}")
        raise


def logout_bitwarden():
    """
    Logs out from Bitwarden CLI.
    """
    try:
        command = shlex.split("bw logout")
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info("Logged out from Bitwarden successfully.")
        else:
            logging.error(f"Failed to logout from Bitwarden. Output: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error during Bitwarden logout: {e.stderr}")

def check_server_configured(api_url):
    try:
        with open("/root/.config/Bitwarden CLI/data.json", "r") as f:
            config_data = json.load(f)
            if "serverUrl" in config_data and config_data["serverUrl"] == api_url:
                logging.info("Server is already configured.")
                return True
            else:
                return False
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.info("Server is not configured.")
        return False

def configure_server(api_url):
    try:
        command = shlex.split(f"bw config server {api_url}")
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info("Server configured successfully.")
        else:
            logging.error(f"Failed to configure server. Output: {result.stderr}")
            if "Logout required before server config update" in result.stderr:
                logging.info("Attempting to logout and reconfigure server.")
                logout_bitwarden()
                result = subprocess.run(command, capture_output=True, text=True)
                if result.returncode == 0:
                    logging.info("Server configured successfully after logout.")
                else:
                    logging.error(f"Failed to configure server after logout. Output: {result.stderr}")
                    raise Exception(f"Failed to configure server after logout: {result.stderr}")
            else:
                raise Exception(f"Failed to configure server: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error configuring server: {e.stderr}")
        raise
