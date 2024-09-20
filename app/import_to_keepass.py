import json,os,pyzipper,logging,shutil,time
from tqdm import tqdm
from colorama import init, Fore, Style
from pykeepass import PyKeePass, create_database
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64decode
from argon2.low_level import hash_secret_raw, Type
from dotenv import load_dotenv
from secrets_manager import retrieve_secrets
from bitwarden_client import BitwardenClient, client_settings_from_dict
import time
from terminaltexteffects.effects import effect_rain, effect_beams, effect_decrypt, effect_matrix

##-------------Interactive-------------
init(autoreset=True)
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
    
    
    import_zip_text = "Importing your ZIP file to your KeePass vault. Please wait.. 🔁"
    effect_import_zip = effect_rain.Rain(import_zip_text)
    effect_import_zip.effect_config.final_gradient_frames = 1
    
    with effect_import_zip.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_import_zip:
            terminal.print(frame)
            time.sleep(0.06)  # Ajuste de velocidad de la animación
            print()
            print()
  
          

# Display ASCII art and welcome message
interactive_message()

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Bitwarden client settings
BW_API_URL = os.getenv("API_URL")
BW_IDENTITY_URL = os.getenv("IDENTITY_URL")
BW_ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
BACKUP_DIR = os.getenv("BACKUP_DIR")

if not all([BW_API_URL, BW_IDENTITY_URL, BW_ACCESS_TOKEN, BACKUP_DIR]):
    raise ValueError("One or more environment variables for Bitwarden are not set. Check your .env file.")

# Setup Bitwarden client
bw_client = BitwardenClient(
    client_settings_from_dict(
        {
            "apiUrl": BW_API_URL,
            "identityUrl": BW_IDENTITY_URL,
            "deviceType": "SDK",
            "userAgent": "Python",
        }
    )
)

# Authenticate using the Secret Manager Access Token
try:
    auth_client = bw_client.auth()
    auth_client.login_access_token(BW_ACCESS_TOKEN)
except Exception as e:
    logging.error(f"Error authenticating to Bitwarden: {e}")
    raise


# Retrieve secrets from Bitwarden
secrets = retrieve_secrets(bw_client)

# Check if all necessary secrets are retrieved
required_secrets = ["ENCRYPTION_PASSWORD", "ZIP_PASSWORD", "ZIP_ATTACHMENT_PASSWORD", "KEEPASS_PASSWORD"]
for secret in required_secrets:
    if secret not in secrets:
        raise ValueError(f"Secret {secret} could not be retrieved from Bitwarden.")

ENCRYPTION_PASSWORD = secrets["ENCRYPTION_PASSWORD"]
ZIP_PASSWORD = secrets["ZIP_PASSWORD"]
ZIP_ATTACHMENT_PASSWORD = secrets["ZIP_ATTACHMENT_PASSWORD"]
KEEPASS_PASSWORD = secrets["KEEPASS_PASSWORD"]
TIMESTAMP = os.getenv("TIMESTAMP")

if not TIMESTAMP:
    raise ValueError("TIMESTAMP is not set in the environment variables.")

# Filenames using the TIMESTAMP
ENCRYPTED_ZIP_FILENAME = f"bw-backup_{TIMESTAMP}.zip"
KEEPASS_DB_FILENAME = f"bw-import-keepass_{TIMESTAMP}.kdbx"

# Paths of files using the filenames
ENCRYPTED_ZIP_FILE_PATH = os.path.join(BACKUP_DIR, ENCRYPTED_ZIP_FILENAME)
KEEPASS_DB_PATH = os.path.join(BACKUP_DIR, KEEPASS_DB_FILENAME)

def decrypt(encrypted_data, password):
    """
    Decrypt data using Argon2.

    Args:
        encrypted_data (bytes): The data to decrypt.
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
        logging.error(f"Error decrypting data: {e}")
        raise

def create_keepass_db(keepass_db, password):
    """
    Create a KeePass database.

    Args:
        keepass_db (str): Path to the KeePass database.
        password (str): Password for the KeePass database.

    Raises:
        Exception: If an error occurs while creating the database.
    """
    try:
        create_database(keepass_db, password=password)
        print(f"Created KeePass database at: {keepass_db}")
    except Exception as e:
        print(f"Error creating KeePass database: {e}")

def parse_attachments_file(attachments_file_path):
    """
    Parse the attachments information file.

    Args:
        attachments_file_path (str): Path to the attachments info file.

    Returns:
        dict: Mapping of item IDs to their attachment names.
    """
    attachments_map = {}
    with open(attachments_file_path, 'r') as file:
        for line in file:
            try:
                parts = line.strip().split(',')
                item_id = parts[2].split(':')[1].strip()
                attachment_name = parts[1].split(':')[1].strip()
                if item_id not in attachments_map:
                    attachments_map[item_id] = []
                attachments_map[item_id].append(attachment_name)
            except ValueError:
                logging.error(f"Line format incorrect in attachments file: {line.strip()}")
    return attachments_map

def import_bitwarden_json_to_keepass(json_data, attachments, attachments_map, keepass_db, password):
    """
    Import Bitwarden JSON data to KeePass.

    Args:
        json_data (str): JSON data from Bitwarden.
        attachments (dict): Attachments data.
        attachments_map (dict): Mapping of item IDs to attachment names.
        keepass_db (str): Path to the KeePass database.
        password (str): Password for the KeePass database.

    Raises:
        Exception: If an error occurs during import.
    """
    try:
        kp = PyKeePass(keepass_db, password=password)
        data = json.loads(json_data)

        folder_map = {}
        if 'folders' in data:
            for folder in data['folders']:
                kp_group = kp.add_group(kp.root_group, folder['name'])
                folder_map[folder['id']] = kp_group

        if 'items' not in data:
            print("Error: 'items' key not found in Bitwarden JSON data.")
            return

        for item in tqdm(data['items'], desc=Fore.GREEN + "Import KeePass" + Fore.RESET, bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.BLUE, Fore.RESET), unit="item"):
            group = kp.root_group
            if item.get('folderId') and item['folderId'] in folder_map:
                group = folder_map[item['folderId']]

            entry = None
            notes = item.get('notes', '') or ''  # Ensure notes is a string
            if item.get('type') == 1 and 'login' in item:
                # Import login items
                title = item.get('name', '') or ''
                username = item['login'].get('username', '') or ''
                password = item['login'].get('password', '') or ''
                uris = item['login'].get('uris', [])
                url = uris[0].get('uri', '') if uris else ''
                totp = item['login'].get('totp', '') or ''

                entry = kp.add_entry(
                    group,
                    title=title,
                    username=username,
                    password=password,
                    url=url,
                    notes=notes
                )

                if totp:
                    entry.otp = f'otpauth://totp/{username}?secret={totp}&issuer={title}'

            elif item.get('type') == 2:
                # Import secure note items
                title = item.get('name', '') or ''
                notes = item.get('notes', '') or ''

                entry = kp.add_entry(
                    group,
                    title=title,
                    username='',
                    password='',
                    url='',
                    notes=notes
                )
            elif item.get('type') == 3 and 'card' in item:
                # Import credit card items
                card = item['card']
                title = f"{item.get('name', '')} - {card.get('brand', '')} - {card.get('number', '')}"
                notes = f"Cardholder Name: {card.get('cardholderName', '')}\n" \
                        f"Expiration: {card.get('expMonth', '')}/{card.get('expYear', '')}\n" \
                        f"Security Code: {card.get('code', '')}"
                entry = kp.add_entry(
                    group,
                    title=title,
                    username='',  # No username for credit cards
                    password='',  # No password for credit cards
                    url='',       # No URL for credit cards
                    notes=notes
                )
            elif item.get('type') == 4 and 'identity' in item:
                # Import identity items
                identity = item['identity']
                title = item.get('name', '') or ''
                notes = f"Title: {identity.get('title', '')}\n" \
                        f"Name: {identity.get('firstName', '')} {identity.get('middleName', '')} {identity.get('lastName', '')}\n" \
                        f"Address: {identity.get('address1', '')} {identity.get('address2', '')} {identity.get('address3', '')}\n" \
                        f"Email: {identity.get('email', '')}\n" \
                        f"Phone: {identity.get('phone', '')}\n" \
                        f"SSN: {identity.get('ssn', '')}\n" \
                        f"Passport Number: {identity.get('passportNumber', '')}\n" \
                        f"License Number: {identity.get('licenseNumber', '')}"
                entry = kp.add_entry(
                    group,
                    title=title,
                    username='',  # No username for identities
                    password='',  # No password for identities
                    url='',       # No URL for identities
                    notes=notes
                )
            else:
                print(f"Error: Unknown item type or missing keys in item {item}.")
                continue

            # Add attachments to the correct item
            item_id = item['id']
            if item_id in attachments_map:
                for attachment_name in attachments_map[item_id]:
                    if attachment_name in attachments:
                        attachment_file = attachments[attachment_name]
                        with open(attachment_file, "rb") as af:
                            attachment_data = af.read()
                        binary_id = kp.add_binary(attachment_data)
                        entry.add_attachment(binary_id, attachment_name)
                    else:
                        print(f"Attachment file {attachment_name} does not exist.")
        
        kp.save()
        print(f"Imported {len(data['items'])} items into the KeePass database.")
    except json.JSONDecodeError as jde:
        print(f"Error reading Bitwarden JSON file: {jde}")
    except IOError as ioe:
        print(f"IO error handling the file: {ioe}")
    except Exception as e:
        print(f"Error importing Bitwarden JSON file to KeePass: {e}")

def main():
    """
    Main function to execute the import process.

    Raises:
        Exception: If an error occurs during the process.
    """
    if not os.path.exists(ENCRYPTED_ZIP_FILE_PATH):
        print(f"The file {ENCRYPTED_ZIP_FILE_PATH} does not exist.")
        return

    temp_dir = os.path.join("/tmp", f"decrypted_zip_{TIMESTAMP}")
    os.makedirs(temp_dir, exist_ok=True)

    try:
        # Unzip the main encrypted ZIP file
        with pyzipper.AESZipFile(ENCRYPTED_ZIP_FILE_PATH, 'r') as zf:
            zf.pwd = ZIP_PASSWORD.encode()
            zf.extractall(temp_dir)
        
        print(f"Decrypted ZIP contents extracted to temporary directory.")

        encrypted_json_file_path = os.path.join(temp_dir, f"bw-backup_{TIMESTAMP}.json")

        if not os.path.exists(encrypted_json_file_path):
            print(f"The file {encrypted_json_file_path} does not exist.")
            return

        with open(encrypted_json_file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = decrypt(encrypted_data.decode('utf-8'), ENCRYPTION_PASSWORD)

        attachments = {}
        attachments_zip_file_path = os.path.join(temp_dir, f"attachments_{TIMESTAMP}.zip")
        if os.path.exists(attachments_zip_file_path):
            with pyzipper.AESZipFile(attachments_zip_file_path, 'r') as zf:
                zf.pwd = ZIP_ATTACHMENT_PASSWORD.encode()
                zf.extractall(temp_dir)

            attachments_file_path = os.path.join(temp_dir, "attachments_info.txt")
            attachments_map = parse_attachments_file(attachments_file_path)
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file != "attachments_info.txt":
                        attachments[file] = os.path.join(root, file)

        create_keepass_db(KEEPASS_DB_PATH, KEEPASS_PASSWORD)
        import_bitwarden_json_to_keepass(decrypted_data, attachments, attachments_map, KEEPASS_DB_PATH, KEEPASS_PASSWORD)
    
    finally:
        # Ensure all temporary files and directories are removed
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        #print(f"Temporary files and directories have been removed.")

if __name__ == "__main__":
    main()

#--------------------------------
    print("\n")
    
    success_text = "Successful Import to Keepass Database"
    effect_success = effect_decrypt.Decrypt(success_text)
    effect_success.effect_config.final_gradient_frames = 1
    
    with effect_success.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_success:
            terminal.print(frame)
            time.sleep(0.01)  # Ajuste de velocidad de la animación 
            print()
            print("\n")