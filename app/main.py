from imports import logging, time, boto3
from config import load_environment_variables, configure_logging
from bitwarden_client import setup_bitwarden_client, authenticate_bitwarden_client, unlock_vault, is_vault_unlocked, check_server_configured, configure_server, logout_bitwarden
from secrets_manager import retrieve_secrets
from backup import backup_bitwarden
from colorama import init, Fore, Style  # Importar colorama
import time
from terminaltexteffects.effects import effect_rain, effect_beams

def clear_screen():
    """
    Clear the terminal screen.
    """
    print("\033c", end="")  # Clear the terminal
    
def display_ascii_art():
    """
    Display ASCII art with Beam effect animation.
    """
    art = """
█░░ ▄▀█ ▀█ █▄█ █░█░█ ▄▀█ █▀█ █▀▄ █▀▀ █▄░█
█▄▄ █▀█ █▄ ░█░ ▀▄▀▄▀ █▀█ █▀▄ █▄▀ ██▄ █░▀█
    """
    effect = effect_beams.Beams(art)
    effect.effect_config.final_gradient_frames = 1
    
    with effect.terminal_output(end_symbol=" ") as terminal:
        for frame in effect:
            terminal.print(frame)
            time.sleep(0.02)  # Ajuste de velocidad de la animación

def interactive_message():
    """
    Display an interactive welcome message with loading animation.
    """
    print("\033c", end="")  # Clear the terminal

    # Welcome message with Rain effect
    welcome_text = "WELCOME TO LAZYWARDEN"
    effect_welcome = effect_rain.Rain(welcome_text)
    effect_welcome.effect_config.final_gradient_frames = 1
    
    with effect_welcome.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_welcome:
            terminal.print(frame)
            time.sleep(0.06)  # Ajuste de velocidad de la animación
            print()

    # Additional ASCII art below the welcome message with Beams effect
    additional_art1 = """
       ________
      | |____| |
      |   __   |
      |  (__)  |
      |        |
      |________|
    """
    
    effect_additional1 = effect_rain.Rain(additional_art1)
    effect_additional1.effect_config.final_gradient_frames = 1
    
    with effect_additional1.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_additional1:
            terminal.print(frame)
            time.sleep(0.02)  # Ajuste de velocidad de la animación
            print()

    # Loading message with Rain effect
    loading_text = "Loading, please wait..."
    effect_loading = effect_rain.Rain(loading_text)
    effect_loading.effect_config.final_gradient_frames = 1
    
    with effect_loading.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_loading:
            terminal.print(frame)
            time.sleep(0.05)
 
    clear_screen()
    display_ascii_art()
    print("\n")

    # Backup start message with Rain effect
    backup_text = "Starting Bitwarden Vault Backup"
    effect_backup = effect_rain.Rain(backup_text)
    effect_backup.effect_config.final_gradient_frames = 1
    
    with effect_backup.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_backup:
            terminal.print(frame)
            time.sleep(0.04)
            print()
            print("\n")

    # Secure backup message with Beams effect
    secure_text = "Please wait while we securely back up your vault data... 🔄"
    effect_secure = effect_beams.Beams(secure_text)
    effect_secure.effect_config.final_gradient_frames = 1
    
    with effect_secure.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_secure:
            terminal.print(frame)
            time.sleep(0.01)  # Ajuste de velocidad de la animación
            print()
            print("\n")
            
def main():
    """
    Main function to load environment variables, configure logging, setup Bitwarden client,
    authenticate client, retrieve secrets, and perform backup.
    """
    interactive_message()

    # Load environment variables
    try:
        env_vars = load_environment_variables()
        logging.info("Environment variables loaded successfully")
    except Exception as e:
        logging.error(f"Error loading environment variables: {e}")
        return

    # Configure logging
    configure_logging()
    logging.info("Logging configured successfully")

    # Check if the server is already configured
    if not check_server_configured(env_vars["API_URL"]):
        try:
            configure_server(env_vars["API_URL"])
            logging.info("Server configured successfully")
        except Exception as e:
            logging.error(f"Error configuring server: {e}")
            return

    # Setup Bitwarden client
    try:
        bw_client = setup_bitwarden_client(env_vars["API_URL"], env_vars["IDENTITY_URL"])
        logging.info("Bitwarden client setup successfully")
    except Exception as e:
        logging.error(f"Error setting up Bitwarden client: {e}")
        return

    # Authenticate Bitwarden client
    try:
        authenticate_bitwarden_client(bw_client, env_vars["ACCESS_TOKEN"])
        logging.info("Bitwarden client authenticated successfully")
    except Exception as e:
        logging.error(f"Error authenticating Bitwarden client: {e}")
        return

    # Retrieve secrets from Bitwarden Secret Manager
    try:
        secrets = retrieve_secrets(bw_client)
        logging.info("Secrets retrieved successfully")
    except Exception as e:
        logging.error(f"Error retrieving secrets: {e}")
        return

    # Check if the vault is already unlocked
    if not is_vault_unlocked():
        # Try to unlock Bitwarden vault using retrieved secrets
        try:
            unlock_vault(secrets["BW_PASSWORD"])
            logging.info("Bitwarden vault unlocked successfully")
        except Exception as e:
            logging.error(f"Error unlocking Bitwarden vault: {e}")
            logging.error("Logging out from Bitwarden.")
            logout_bitwarden()
            return

    logging.info("Environment variables and secrets loaded successfully.")

    # Configure Google Drive
    try:
        if env_vars["GOOGLE_SERVICE_ACCOUNT_FILE"] and env_vars["GOOGLE_FOLDER_ID"]:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build
            SCOPES = ['https://www.googleapis.com/auth/drive']
            credentials = service_account.Credentials.from_service_account_file(env_vars["GOOGLE_SERVICE_ACCOUNT_FILE"], scopes=SCOPES)
            drive_service = build('drive', 'v3', credentials=credentials, cache_discovery=False)
            logging.info("Google Drive configured successfully")
        else:
            drive_service = None
            logging.warning("Google Drive is not configured. Uploads to Google Drive will be skipped.")
    except Exception as e:
        logging.error(f"Error configuring Google Drive: {e}")
        drive_service = None

    # Perform Bitwarden backup
    try:
        backup_bitwarden(env_vars, secrets, drive_service)
        logging.info("Bitwarden backup completed successfully")
    except Exception as e:
        logging.error(f"Error during backup: {e}")

    # Check if the vault is locked after backup and unlock if necessary
    if not is_vault_unlocked():
        try:
            unlock_vault(secrets["BW_PASSWORD"])
            logging.info("Bitwarden vault unlocked successfully after backup")
        except Exception as e:
            logging.error(f"Error unlocking Bitwarden vault after backup: {e}")
            logging.error("Logging out from Bitwarden.")
            logout_bitwarden()
            return

if __name__ == "__main__":
    configure_logging()
    main()
