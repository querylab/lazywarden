from imports import os, subprocess, logging, json, pyzipper, time, hashlib
from base64 import urlsafe_b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
from dotenv import load_dotenv
from bitwarden_client import BitwardenClient, client_settings_from_dict, DeviceType, login_bitwarden, unlock_vault
from secrets_manager import retrieve_secrets
from config import configure_logging
from tqdm import tqdm
from colorama import init, Fore
import time
from terminaltexteffects.effects import effect_rain, effect_beams, effect_wipe, effect_matrix

# Initialize colorama
init(autoreset=True)

def load_environment_variables():
    """
    Load environment variables from a .env file.
    """
    load_dotenv()
    return {
        "TIMESTAMP": os.getenv("TIMESTAMP"),
        "BACKUP_DIR": os.getenv("BACKUP_DIR")
    }

##-------------Interactive-------------

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
    print()
    print("\n")

##-------------------------------------

   
    press_enter_text = "Please press Enter to continue."
    effect_press_enter = effect_rain.Rain(press_enter_text)
    effect_press_enter.effect_config.final_gradient_frames = 1
    
    with effect_press_enter.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_press_enter:
            terminal.print(frame)
            time.sleep(0.06)  # Ajuste de velocidad de la animación
            print()
            print()
      

    input()
    
    
    import_zip_text = "Importing your ZIP file to your Bitwarden vault. Please wait.. 🔁"
    effect_import_zip = effect_wipe.Wipe(import_zip_text)
    effect_import_zip.effect_config.final_gradient_frames = 1
    
    with effect_import_zip.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_import_zip:
            terminal.print(frame)
            time.sleep(0.06)  # Ajuste de velocidad de la animación
            print()
            print()
  
          

# Load environment variables and configure logging
env_vars = load_environment_variables()
configure_logging()


def decrypt(encrypted_data, password):
    """
    Decrypt data using Argon2.

    Args:
        encrypted_data (str): The encrypted data.
        password (str): The password used for decryption.

    Returns:
        bytes: The decrypted data.

    Raises:
        Exception: If an error occurs during decryption.
    """
    try:
        missing_padding = len(encrypted_data) % 4
        if missing_padding:
            encrypted_data += '=' * (4 - missing_padding)
        encrypted_data = urlsafe_b64decode(encrypted_data)
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_data = encrypted_data[32:]
        key = hash_secret_raw(password.encode(), salt, time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, type=Type.I)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_data
    except Exception as e:
        logging.error(f"{Fore.RED}Error decrypting data: {e}")
        raise

def calculate_hash(file_path):
    """
    Calculate SHA-256 hash of a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        str: The SHA-256 hash of the file.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def verify_backup_integrity(zip_filepath, expected_hash):
    """
    Verify the integrity of a backup file by comparing its hash.

    Args:
        zip_filepath (str): Path to the ZIP file.
        expected_hash (str): The expected hash value.

    Returns:
        bool: True if the hash matches, False otherwise.
    """
    calculated_hash = calculate_hash(zip_filepath)
    if calculated_hash == expected_hash:
        logging.info(f"{Fore.GREEN}File integrity verified successfully.")
        return True
    else:
        logging.error(f"{Fore.RED}File integrity check failed. Expected {expected_hash} but got {calculated_hash}")
        return False

def inspect_json_file(json_file_path):
    """
    Inspect a JSON file to ensure it contains data.

    Args:
        json_file_path (str): Path to the JSON file.

    Returns:
        bool: True if the file contains data, False otherwise.
    """
    try:
        with open(json_file_path, "r") as file:
            data = json.load(file)
            if not data:
                logging.error(f"{Fore.RED}The JSON file {json_file_path} is empty.")
                return False
            logging.info(f"{Fore.GREEN}The JSON file {json_file_path} contains data.")
            return True
    except json.JSONDecodeError as e:
        logging.error(f"{Fore.RED}Error decoding JSON file {json_file_path}: {e}")
        return False
    except Exception as e:
        logging.error(f"{Fore.RED}Unexpected error reading JSON file {json_file_path}: {e}")
        return False

def list_bitwarden_items(bw_session):
    """
    List items in the Bitwarden vault.

    Args:
        bw_session (str): Bitwarden session token.

    Returns:
        dict: A dictionary mapping item names to item IDs.
    """
    try:
        result = subprocess.run(
            ["/usr/local/bin/bw", "list", "items", "--session", bw_session],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            logging.error(f"{Fore.RED}Error listing Bitwarden items: {result.stderr}")
            return {}
        items = json.loads(result.stdout)
        item_dict = {item["name"]: item["id"] for item in items}
        return item_dict
    except json.JSONDecodeError as e:
        logging.error(f"{Fore.RED}Error decoding JSON response: {e}")
        return {}
    except subprocess.CalledProcessError as e:
        logging.error(f"{Fore.RED}Error listing Bitwarden items: {str(e)}")
        return {}


def authenticate_bitwarden_client(bw_client, access_token):
    """
    Authenticates the Bitwarden client using an access token.

    Args:
        bw_client (BitwardenClient): Bitwarden client instance.
        access_token (str): Access token for authentication.

    Raises:
        Exception: If authentication fails.
    """
    try:
        # Authenticate using the access token
        auth_client = bw_client.auth()
        auth_client.login_access_token(access_token)
        logging.info("Successfully authenticated using the access token.")
    except Exception as e:
        logging.error(f"Error al autenticar con Bitwarden: {e}")
        raise


def restore_items_and_attachments(env_vars, secrets, bw_session, sleep_milliseconds=500):
    """
    Restore items and attachments to the Bitwarden vault.

    Args:
        env_vars (dict): Environment variables.
        secrets (dict): Secrets required for decryption.
        bw_session (str): Bitwarden session token.
        sleep_milliseconds (int, optional): Time to sleep between operations. Defaults to 500.
    """
    timestamp = env_vars["TIMESTAMP"]
    zip_filepath = os.path.join(env_vars["BACKUP_DIR"], f"bw-backup_{timestamp}.zip")
    decrypted_zip_dir_path = os.path.join(env_vars["BACKUP_DIR"], "decrypted_zip")
    decrypted_json_file_path = os.path.join(decrypted_zip_dir_path, f"bw-backup_{timestamp}.json")
    decrypted_attachments_dir_path = os.path.join(decrypted_zip_dir_path, "attachments")

    hash_filepath = f"{zip_filepath}.hash"
    try:
        with open(hash_filepath, "r") as hash_file:
            expected_hash = hash_file.read().strip()
    except FileNotFoundError:
        logging.error(f"{Fore.RED}Hash file not found for {zip_filepath}. Please verify the backup integrity.")
        print(f"{Fore.RED}Hash file not found for {zip_filepath}. Please verify the backup integrity.")
        return

    if not verify_backup_integrity(zip_filepath, expected_hash):
        logging.error(f"{Fore.RED}Backup file integrity check failed. Aborting restore operation.")
        print(f"{Fore.RED}Backup file integrity check failed. Aborting restore operation.")
        return

    if not os.path.exists(zip_filepath):
        logging.error(f"The file {zip_filepath} does not exist.")
        return

    try:
        os.makedirs(decrypted_zip_dir_path, exist_ok=True)
        os.makedirs(decrypted_attachments_dir_path, exist_ok=True)

        logging.info(f"Unzipping the main encrypted ZIP file: {zip_filepath}")
        with pyzipper.AESZipFile(zip_filepath, 'r') as zf:
            zf.pwd = secrets["ZIP_PASSWORD"].encode()
            zf.extractall(decrypted_zip_dir_path)
        logging.info(f"Decrypted ZIP contents saved to {decrypted_zip_dir_path}")

        if not os.path.exists(decrypted_json_file_path):
            logging.error(f"The file {decrypted_json_file_path} does not exist.")
            return
        attachments_zip_file_path = os.path.join(decrypted_zip_dir_path, f"attachments_{timestamp}.zip")
        if not os.path.exists(attachments_zip_file_path):
            logging.warning(f"No attachments ZIP file found at {attachments_zip_file_path}")

        with open(decrypted_json_file_path, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = decrypt(encrypted_data.decode('utf-8'), secrets["ENCRYPTION_PASSWORD"])

        with open(decrypted_json_file_path, "wb") as f:
            f.write(decrypted_data)
        logging.info(f"Decrypted JSON data saved to {decrypted_json_file_path}")

        if not inspect_json_file(decrypted_json_file_path):
            logging.error(f"Inspection of JSON file {decrypted_json_file_path} failed.")
            print(f"{Fore.RED}Inspection of JSON file {decrypted_json_file_path} failed. Please check the file content.")
            return

        if os.path.exists(attachments_zip_file_path):
            logging.info(f"Unzipping the attachments ZIP file: {attachments_zip_file_path}")
            with pyzipper.AESZipFile(attachments_zip_file_path, 'r') as zf:
                zf.pwd = secrets["ZIP_ATTACHMENT_PASSWORD"].encode()
                zf.extractall(decrypted_attachments_dir_path)
            logging.info(f"Decrypted attachments saved to {decrypted_attachments_dir_path}")

        attachments_info_file_path = os.path.join(decrypted_attachments_dir_path, "attachments_info.txt")
        if not os.path.exists(attachments_info_file_path):
            logging.error(f"The file {attachments_info_file_path} does not exist.")
            return

        logging.info("Listing files in the attachments directory:")
        for root, dirs, files in os.walk(decrypted_attachments_dir_path):
            for file in files:
                logging.info(f"Found file: {file}")
                
        interactive_message()

        # Adjust log level to ERROR to suppress INFO messages
        original_log_level = logging.getLogger().level
        logging.getLogger().setLevel(logging.ERROR)

        help_result = subprocess.run(["/usr/local/bin/bw", "import", "--formats"], capture_output=True, text=True)
        logging.info(f"Bitwarden CLI import formats: {help_result.stdout}")

        try:
            result = subprocess.run(["/usr/local/bin/bw", "import", "bitwardenjson", decrypted_json_file_path, "--session", bw_session], capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"Error during import: {result.stderr}")
                raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
            logging.info(f"Backup imported to Bitwarden successfully")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error during import: {e}. Trying to unlock the vault again.")
            bw_session = unlock_vault(secrets["BW_PASSWORD"])
            if bw_session:
                result = subprocess.run(["/usr/local/bin/bw", "import", "bitwardenjson", decrypted_json_file_path, "--session", bw_session], capture_output=True, text=True)
                if result.returncode != 0:
                    logging.error(f"Error during import after unlocking the vault: {result.stderr}")
                    raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
                logging.info(f"Backup imported to Bitwarden successfully after unlocking the vault")

        logging.info(f"Restoring items finished")

        for _ in tqdm(range(100), desc=f"{Fore.GREEN}Bitwarden JSON Import{Fore.RESET}", ncols=100, bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.BLUE, Fore.RESET)):
            time.sleep(0.01)

        # Restore original log level
        logging.getLogger().setLevel(original_log_level)

        bitwarden_items = list_bitwarden_items(bw_session)
        if not bitwarden_items:
            logging.error(f"Failed to retrieve Bitwarden items. Cannot proceed with attachment.")
            return

        attach_files_using_info(attachments_info_file_path, decrypted_attachments_dir_path, bitwarden_items, bw_session, secrets["BW_PASSWORD"])

    except subprocess.CalledProcessError as e:
        logging.getLogger().setLevel(original_log_level)
        logging.error(f"Error during import: {str(e)}")
    except Exception as e:
        logging.getLogger().setLevel(original_log_level)
        logging.error(f"Unexpected error: {str(e)}")
    finally:
        if os.path.exists(decrypted_zip_dir_path):
            subprocess.run(["rm", "-rf", decrypted_zip_dir_path], check=True)

def attach_files_using_info(attachments_info_file_path, attachments_dir, bitwarden_items, bw_session, bw_password):
    """
    Attach files to Bitwarden items based on the information in attachments_info.txt.

    Args:
        attachments_info_file_path (str): Path to the attachments info file.
        attachments_dir (str): Directory containing the attachments.
        bitwarden_items (dict): Dictionary of Bitwarden items.
        bw_session (str): Bitwarden session token.
        bw_password (str): Bitwarden password for unlocking the vault.
    """
    try:
        logging.info(f"{Fore.GREEN}Reading attachments_info.txt")
        with open(attachments_info_file_path, "r") as f:
            lines = f.readlines()

        total_lines = len([line for line in lines if line.strip()])

        # Adjust log level to ERROR to suppress INFO messages
        original_log_level = logging.getLogger().level
        logging.getLogger().setLevel(logging.ERROR)

        with tqdm(total=total_lines, desc=f"{Fore.GREEN}Bitwarden Attachments Import{Fore.RESET}", ncols=100, bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.BLUE, Fore.RESET)) as pbar:
            for line in lines:
                if line.strip():
                    logging.info(f"Processing line: {line.strip()}")
                    parts = line.split(",")
                    if len(parts) != 3:
                        logging.error(f"Unexpected format in line: {line.strip()}")
                        continue
                    try:
                        item_name = parts[0].split(":")[1].strip()
                        attachment_name = parts[1].split(":")[1].strip()
                        attachment_id = parts[2].split(":")[1].strip()
                        item_id = bitwarden_items.get(item_name)
                        if not item_id:
                            logging.error(f"Item {item_name} not found in Bitwarden vault.")
                            continue
                    except IndexError as e:
                        logging.error(f"Error processing line: {line.strip()} - {e}")
                        continue
                    attachment_path = os.path.join(attachments_dir, "attachments", attachment_name)
                    if not os.path.exists(attachment_path):
                        logging.error(f"File {attachment_path} does not exist. Trying root directory.")
                        attachment_path = os.path.join(attachments_dir, attachment_name)
                    logging.info(f"Attachment path: {attachment_path}")
                    if os.path.exists(attachment_path):
                        logging.info(f"Attaching {attachment_name} to item ID: {item_id} with attachment ID: {attachment_id}")
                        cmd = ["/usr/local/bin/bw", "create", "attachment", "--file", f"./{attachment_name}", "--itemid", item_id, "--session", bw_session]
                        try:
                            result = subprocess.run(cmd, cwd=os.path.dirname(attachment_path), capture_output=True, text=True)
                            logging.info(f"Subprocess result: {result}")
                            if result.returncode != 0:
                                logging.error(f"Error attaching {attachment_name} to item ID: {item_id}: {result.stderr}")
                                bw_session = unlock_vault(bw_password)
                                if bw_session:
                                    result = subprocess.run(cmd, cwd=os.path.dirname(attachment_path), capture_output=True, text=True)
                                    logging.info(f"Subprocess result after unlocking vault: {result}")
                                    if result.returncode != 0:
                                        logging.error(f"Error attaching {attachment_name} to item ID after unlocking the vault: {result.stderr}")
                                    else:
                                        logging.info(f"Successfully attached {attachment_name} to item ID: {item_id}")
                            else:
                                logging.info(f"Successfully attached {attachment_name} to item ID: {item_id}")
                        except subprocess.CalledProcessError as e:
                            logging.error(f"Error attaching files: {str(e)}")
                    else:
                        logging.error(f"File {attachment_path} does not exist")
                    pbar.update(1)

        # Restore original log level
        logging.getLogger().setLevel(original_log_level)


    except Exception as e:
        logging.getLogger().setLevel(original_log_level)
        logging.error(f"Error attaching files: {str(e)}")

if __name__ == "__main__":
    env_vars = load_environment_variables()

    bw_client = BitwardenClient(
        client_settings_from_dict(
            {
                "apiUrl": os.getenv("API_URL"),
                "deviceType": DeviceType.SDK,
                "identityUrl": os.getenv("IDENTITY_URL"),
                "userAgent": "Python",
            }
        )
    )

    try:
        authenticate_bitwarden_client(bw_client, os.getenv("ACCESS_TOKEN"))

        secrets = retrieve_secrets(bw_client)

        bw_session = login_bitwarden(secrets["BW_USERNAME"], secrets["BW_PASSWORD"], secrets["BW_TOTP_SECRET"])
        if bw_session is None:
            logging.error("Failed to obtain Bitwarden session")
            exit(1)

    except Exception as e:
        logging.error(f"Error authenticating to Bitwarden: {e}")
        raise

    restore_items_and_attachments(env_vars, secrets, bw_session)

#--------------------------------
    print("\n")
    
    success_text = "Successful Import to Bitwarden Vault"
    effect_success = effect_wipe.Wipe(success_text)
    effect_success.effect_config.final_gradient_frames = 1
    
    with effect_success.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_success:
            terminal.print(frame)
            time.sleep(0.07)  # Ajuste de velocidad de la animación 
            print()
            print("\n")
