from imports import json, requests, dropbox, pyzipper, logging, subprocess, os, pcloud, nextcloud_client, arrow, time, boto3, hashlib
from mega import Mega
from tqdm import tqdm
from bitwarden_sdk import BitwardenClient, DeviceType, client_settings_from_dict
from secrets_manager import retrieve_secrets
from notifications import send_telegram_notification, send_discord_notification, send_slack_notification, send_email_with_attachment
from googleapiclient.http import MediaFileUpload
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
from argon2.low_level import hash_secret_raw, Type
from caldav import DAVClient
from icalendar import Calendar as iCalendar, Event as iEvent
from requests.exceptions import RequestException
from colorama import init, Fore, Style, Back
from dotenv import load_dotenv
init(autoreset=True)
from bitwarden_client import login_bitwarden
from botocore.client import Config
import pytz

# Carga las variables de entorno desde el archivo .env
load_dotenv()

# Obtén la zona horaria de las variables de entorno
TIMEZONE = os.getenv('TIMEZONE')

def load_environment_variables():
    """
    Load environment variables.

    Returns:
        dict: Dictionary of environment variables.
    """
    # Implement your function to load environment variables
    pass

def configure_logging():
    """
    Configure logging settings.
    """
    # Implement your function to configure logging
    pass

def refresh_dropbox_token(dropbox_refresh_token, dropbox_app_key, dropbox_app_secret):
    """
    Refresh Dropbox access token using refresh token.

    Args:
        dropbox_refresh_token (str): Dropbox refresh token.
        dropbox_app_key (str): Dropbox app key.
        dropbox_app_secret (str): Dropbox app secret.

    Returns:
        str: New Dropbox access token.

    Raises:
        Exception: If an error occurs while refreshing the token.
    """
    try:
        response = requests.post(
            'https://api.dropboxapi.com/oauth2/token',
            data={'grant_type': 'refresh_token', 'refresh_token': dropbox_refresh_token},
            auth=(dropbox_app_key, dropbox_app_secret),
            timeout=10
        )
        response.raise_for_status()
        tokens = response.json()
        return tokens['access_token']
    except Exception as e:
        logging.error(f"{Fore.RED}Error refreshing Dropbox token: {e}")
        raise

def encrypt(data, password):
    """
    Encrypt data using AES and Argon2 for key derivation.

    Args:
        data (bytes): Data to encrypt.
        password (str): Password for encryption.

    Returns:
        bytes: Encrypted data.

    Raises:
        Exception: If an error occurs during encryption.
    """
    try:
        salt = os.urandom(16)
        key = hash_secret_raw(password.encode(), salt, time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, type=Type.I)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        return urlsafe_b64encode(salt + iv + encrypted_data)
    except Exception as e:
        logging.error(f"{Fore.RED}Error encrypting data: {e}")
        raise

def decrypt(encrypted_data, password):
    """
    Decrypt data using AES and Argon2 for key derivation.

    Args:
        encrypted_data (bytes): Data to decrypt.
        password (str): Password for decryption.

    Returns:
        bytes: Decrypted data.

    Raises:
        Exception: If an error occurs during decryption.
    """
    try:
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
        str: SHA-256 hash of the file.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def create_folder_if_not_exists(drive_service, folder_name, parent_folder_id=None):
    """
    Create a folder in Google Drive if it doesn't exist.

    Args:
        drive_service: Google Drive service instance.
        folder_name (str): Name of the folder to create.
        parent_folder_id (str, optional): ID of the parent folder.

    Returns:
        str: ID of the created or existing folder.

    Raises:
        Exception: If an error occurs while creating the folder.
    """
    query = f"name = '{folder_name}' and mimeType = 'application/vnd.google-apps.folder'"
    if parent_folder_id:
        query += f" and '{parent_folder_id}' in parents"
    results = drive_service.files().list(q=query, fields="files(id, name)").execute()
    items = results.get('files', [])
    if not items:
        folder_metadata = {
            'name': folder_name,
            "mimeType": "application/vnd.google-apps.folder",
            'parents': [parent_folder_id] if parent_folder_id else []
        }
        try:
            created_folder = drive_service.files().create(
                body=folder_metadata,
                fields='id'
            ).execute()
            logging.info(f"{Fore.GREEN}Created Folder ID: {created_folder['id']}")
            return created_folder["id"]
        except Exception as e:
            logging.error(f"{Fore.RED}Error creating folder: {e}")
            raise
    else:
        logging.info(f"{Fore.GREEN}Folder '{folder_name}' already exists with ID: {items[0]['id']}")
        return items[0]['id']

def upload_file_to_drive(drive_service, file_path, folder_id):
    """
    Upload a file to Google Drive.

    Args:
        drive_service: Google Drive service instance.
        file_path (str): Path to the file to upload.
        folder_id (str): ID of the folder to upload to.

    Raises:
        Exception: If an error occurs while uploading the file.
    """
    file_metadata = {
        'name': os.path.basename(file_path),
        'parents': [folder_id]
    }
    media = MediaFileUpload(file_path, resumable=True)
    try:
        file = drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        logging.info(f"{Fore.GREEN}File ID: {file.get('id')}")
    except Exception as e:
        logging.error(f"{Fore.RED}Error uploading file to Drive: {e}")
        raise

def create_pcloud_folder_if_not_exists(pc, folder_path):
    """
    Create a folder in pCloud if it doesn't exist.

    Args:
        pc: pCloud client instance.
        folder_path (str): Path of the folder to create.

    Raises:
        Exception: If an error occurs while creating the folder.
    """
    try:
        response = pc.listfolder(folderid=0)
        if response['result'] == 0:
            folder_exists = any(item['name'] == folder_path.strip('/') for item in response['metadata']['contents'])
            if not folder_exists:
                pc.createfolder(path=f'/{folder_path.strip("/")}')
                logging.info(f"{Fore.GREEN}Folder '{folder_path}' created in pCloud")
            else:
                logging.info(f"{Fore.GREEN}Folder '{folder_path}' already exists in pCloud")
        else:
            logging.error(f"{Fore.RED}Error listing root folder in pCloud: {response}")
            raise Exception("Failed to list root folder in pCloud")
    except Exception as e:
        logging.error(f"{Fore.RED}Error creating folder in pCloud: {e}")
        raise

def upload_file_to_pcloud(file_path, folder_path, pcloud_username, pcloud_password):
    """
    Upload a file to pCloud.

    Args:
        file_path (str): Path to the file to upload.
        folder_path (str): Path of the folder to upload to.
        pcloud_username (str): pCloud username.
        pcloud_password (str): pCloud password.

    Raises:
        Exception: If an error occurs while uploading the file.
    """
    try:
        pc = pcloud.PyCloud(pcloud_username, pcloud_password)
        create_pcloud_folder_if_not_exists(pc, folder_path)
        response = pc.uploadfile(files=[file_path], path=f'/{folder_path.strip("/")}')
        if response['result'] == 0:
            logging.info(f"{Fore.GREEN}File uploaded to pCloud")
        else:
            logging.error(f"{Fore.RED}Error uploading file to pCloud: {response}")
            raise Exception("Failed to upload file to pCloud")
        pc.logout()
    except Exception as e:
        logging.error(f"{Fore.RED}Error uploading to pCloud: {e}")
        raise

def upload_file_to_mega(file_path, mega_email, mega_password):
    """
    Upload a file to Mega.

    Args:
        file_path (str): Path to the file to upload.
        mega_email (str): Mega email.
        mega_password (str): Mega password.

    Raises:
        Exception: If an error occurs while uploading the file.
    """
    try:
        mega = Mega()
        m = mega.login(mega_email, mega_password)
        folder = m.find('bitwarden-drive-backup')
        if not folder:
            m.create_folder('bitwarden-drive-backup')
            folder = m.find('bitwarden-drive-backup')
        m.upload(file_path, folder[0])
        logging.info(f"{Fore.GREEN}File uploaded to Mega")
    except Exception as e:
        logging.error(f"{Fore.RED}Error uploading to Mega: {e}")
        raise

def get_or_create_todoist_project(todoist_token, project_name):
    """
    Retrieve or create a Todoist project.

    Args:
        todoist_token (str): Todoist token.
        project_name (str): Name of the project to retrieve or create.

    Returns:
        str: ID of the retrieved or created project.

    Raises:
        Exception: If an error occurs while retrieving or creating the project.
    """
    headers = {"Authorization": f"Bearer {todoist_token}", "Content-Type": "application/json"}
    response = requests.get("https://api.todoist.com/rest/v2/projects", headers=headers, timeout=10)
    if response.status_code != 200:
        logging.error(f"{Fore.RED}Failed to fetch Todoist projects")
        raise Exception("Failed to fetch Todoist projects")
    projects = response.json()
    project = next((p for p in projects if p["name"] == project_name), None)
    if project:
        return project["id"]
    else:
        payload = {"name": project_name, "color": "blue"}
        response = requests.post("https://api.todoist.com/rest/v2/projects", headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            project = response.json()
            return project["id"]
        else:
            logging.error(f"{Fore.RED}Failed to create Todoist project")
            raise Exception("Failed to create Todoist project")

def upload_file_to_nextcloud(file_path, nextcloud_url, nextcloud_username, nextcloud_password):
    """
    Upload a file to Nextcloud.

    Args:
        file_path (str): Path to the file to upload.
        nextcloud_url (str): Nextcloud URL.
        nextcloud_username (str): Nextcloud username.
        nextcloud_password (str): Nextcloud password.

    Raises:
        Exception: If an error occurs while uploading the file.
    """
    try:
        nc = nextcloud_client.Client(nextcloud_url)
        nc.login(nextcloud_username, nextcloud_password)
        remote_directory = 'bitwarden-drive-backup'
        remote_path = f'{remote_directory}/{os.path.basename(file_path)}'
        try:
            nc.list(remote_directory)
            logging.info(f"{Fore.GREEN}The directory '{remote_directory}' already exists.")
        except nextcloud_client.HTTPResponseError as e:
            if e.status_code == 404:
                nc.mkdir(remote_directory)
                logging.info(f"{Fore.GREEN}Directory '{remote_directory}' created successfully.")
            else:
                logging.error(f"{Fore.RED}Error checking the directory: {e}")
                raise
        nc.put_file(remote_path, file_path)
        logging.info(f"{Fore.GREEN}File uploaded successfully to {remote_path}")
        link_info = nc.share_file_with_link(remote_path)
        logging.info(f"{Fore.GREEN}Here is your link: {link_info.get_link()}")
    except nextcloud_client.HTTPResponseError as e:
        logging.error(f"{Fore.RED}HTTP error: {e.status_code}")
        raise
    except Exception as e:
        logging.error(f"{Fore.RED}Error uploading the file to Nextcloud: {e}")
        raise

def upload_file_to_seafile(file_path, seafile_server_url, username, password, directory='/'):
    """
    Upload a file to Seafile.

    Args:
        file_path (str): Path to the file to upload.
        seafile_server_url (str): Seafile server URL.
        username (str): Seafile username.
        password (str): Seafile password.
        directory (str, optional): Directory to upload the file to. Defaults to '/'.

    Raises:
        Exception: If an error occurs while uploading the file.
    """
    repo_name = 'bitwarden-drive-backup'
    try:
        login_url = f"{seafile_server_url}/api2/auth-token/"
        login_data = {'username': username, 'password': password}
        response = requests.post(login_url, data=login_data)
        response.raise_for_status()
        token = response.json()['token']
        headers = {'Authorization': f'Token {token}'}
        repos_url = f"{seafile_server_url}/api2/repos/"
        response = requests.get(repos_url, headers=headers)
        response.raise_for_status()
        repos = response.json()
        repo_id = None
        for repo in repos:
            if repo['name'] == repo_name:
                repo_id = repo['id']
                logging.info(f"{Fore.GREEN}Repository {repo_name} already exists with ID: {repo_id}")
                break
        if not repo_id:
            create_repo_url = f"{seafile_server_url}/api2/repos/"
            response = requests.post(create_repo_url, headers=headers, data={'name': repo_name, 'desc': ''})
            response.raise_for_status()
            repo_id = response.json()['repo_id']
            logging.info(f"{Fore.GREEN}Repository {repo_name} created with ID: {repo_id}")
        list_dir_url = f"{seafile_server_url}/api2/repos/{repo_id}/dir/?p={directory}"
        response = requests.get(list_dir_url, headers=headers)
        if response.status_code == 404:
            mkdir_url = f"{seafile_server_url}/api2/repos/{repo_id}/dir/"
            response = requests.post(mkdir_url, headers=headers, data={'p': directory})
            response.raise_for_status()
            logging.info(f"{Fore.GREEN}Directory {directory} created.")
        upload_link_url = f"{seafile_server_url}/api2/repos/{repo_id}/upload-link/?p={directory}"
        response = requests.get(upload_link_url, headers=headers)
        response.raise_for_status()
        upload_link = response.json()
        upload_link = upload_link.replace('http://seafile.example.com', seafile_server_url)
        with open(file_path, 'rb') as file:
            files = {'file': file}
            data = {'parent_dir': directory}
            response = requests.post(upload_link, headers=headers, files=files, data=data)
            response.raise_for_status()
            logging.info(f"{Fore.GREEN}File {os.path.basename(file_path)} uploaded successfully to {directory}")
    except Exception as e:
        logging.error(f"{Fore.RED}Error uploading the file to Seafile: {e}")
        raise

def create_caldav_event(summary, description, location, start, end, caldav_url, caldav_username, caldav_password):
    """
    Create a CalDAV event.

    Args:
        summary (str): Summary of the event.
        description (str): Description of the event.
        location (str): Location of the event.
        start (Arrow): Start time of the event.
        end (Arrow): End time of the event.
        caldav_url (str): CalDAV server URL.
        caldav_username (str): CalDAV username.
        caldav_password (str): CalDAV password.

    Raises:
        Exception: If an error occurs while creating the event.
    """
    try:
        client = DAVClient(caldav_url, username=caldav_username, password=caldav_password)
        principal = client.principal()
        calendars = principal.calendars()
        if not calendars:
            raise Exception("No calendars found for this user")
        calendar_name = "Bitwarden Backup"
        calendar = next((cal for cal in calendars if cal.name == calendar_name), None)
        if not calendar:
            calendar = principal.make_calendar(calendar_name)
            logging.info(f"{Fore.GREEN}Calendar '{calendar_name}' created.")
        cal = iCalendar()
        event = iEvent()
        event.add('summary', summary)
        event.add('description', description)
        event.add('location', location)
        event.add('dtstart', start.datetime)
        event.add('dtend', end.datetime)
        event.add('dtstamp', arrow.utcnow().datetime)
        event['uid'] = f"{arrow.utcnow().format('YYYYMMDDTHHmmss')}@yourdomain.com"
        cal.add_component(event)
        calendar.add_event(cal.to_ical().decode('utf-8'))
        logging.info(f"{Fore.GREEN}Event '{summary}' created in calendar '{calendar_name}' from {start} to {end}")
    except RequestException as re:
        logging.error(f"{Fore.RED}Connection error: {re}")
        raise
    except Exception as e:
        logging.error(f"{Fore.RED}Error: {e}")
        raise

def create_bucket_if_not_exists(s3, bucket_name):
    """
    Create a bucket in Filebase if it doesn't exist.

    Args:
        s3: boto3 client instance.
        bucket_name (str): Filebase bucket name.

    Raises:
        Exception: If an error occurs while creating the bucket.
    """
    try:
        s3.head_bucket(Bucket=bucket_name)
        logging.info(f"Bucket '{bucket_name}' already exists in Filebase.")
    except s3.exceptions.ClientError as e:
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            s3.create_bucket(Bucket=bucket_name)
            logging.info(f"Bucket '{bucket_name}' created in Filebase.")
        else:
            logging.error(f"Error checking bucket: {e}")
            raise

def upload_file_to_filebase(file_path, access_key, secret_key, key_name):
    """
    Upload a file to Filebase.

    Args:
        file_path (str): Path to the file to upload.
        access_key (str): Filebase access key.
        secret_key (str): Filebase secret key.
        key_name (str): Key name for the uploaded file.

    Raises:
        Exception: If an error occurs while uploading the file.
    """
    bucket_name = 'bitwarden-drive-backup'

    try:
        s3 = boto3.client('s3',
                          endpoint_url='https://s3.filebase.com',
                          aws_access_key_id=access_key,
                          aws_secret_access_key=secret_key,
                          config=Config(signature_version='s3v4'))

        # Create the bucket if it doesn't exist
        create_bucket_if_not_exists(s3, bucket_name)

        # Upload the file
        s3.upload_file(file_path, bucket_name, key_name)
        logging.info(f"File {file_path} uploaded to {bucket_name}/{key_name} on Filebase")
    except Exception as e:
        logging.error(f"Error uploading file to Filebase: {e}")
        raise

def backup_bitwarden(env_vars, secrets, drive_service):
    """
    Main function to backup Bitwarden data.

    Args:
        env_vars (dict): Environment variables.
        secrets (dict): Secrets for authentication and encryption.
        drive_service: Google Drive service instance.

    Raises:
        Exception: If an error occurs during the backup process.
    """
    timestamp = arrow.utcnow().format("YYYY_MM_DD_HH_mm_ss")
    zip_filepath = os.path.join(env_vars["BACKUP_DIR"], f"bw-backup_{timestamp}.zip")
    attachments_zip_filepath = os.path.join(env_vars["BACKUP_DIR"], f"attachments_{timestamp}.zip")
    attachments_info_filepath = os.path.join(env_vars["BACKUP_DIR"], "attachments_info.txt")

    os.makedirs(env_vars["BACKUP_DIR"], exist_ok=True)

    try:
        subprocess.run(["/usr/local/bin/bw", "config", "server", secrets["BW_URL"]], check=True)
        bw_session = login_bitwarden(secrets["BW_USERNAME"], secrets["BW_PASSWORD"], secrets["BW_TOTP_SECRET"])
        if bw_session is None:
            logging.error(f"{Fore.RED}Failed to obtain Bitwarden session")
            return
        os.environ['BW_SESSION'] = bw_session
        subprocess.run(["/usr/local/bin/bw", "sync", "--session", bw_session], check=True)
        logging.info(f"{Fore.GREEN}Logged in and synced")
    except subprocess.CalledProcessError as e:
        logging.error(f"{Fore.RED}Error during sync: {str(e)}")
        return
    except Exception as e:
        logging.error(f"{Fore.RED}Unexpected error: {str(e)}")
        return

    progress_stages = [
        {"description": "Exporting Bitwarden data", "update": 10},
        {"description": "Exporting attachments", "update": 10},
        {"description": "Creating ZIP file", "update": 10},
        {"description": "Uploading to Dropbox", "update": 10},
        {"description": "Uploading to Google Drive", "update": 10},
        {"description": "Uploading to pCloud", "update": 10},
        {"description": "Uploading to Mega", "update": 10},
        {"description": "Uploading to Nextcloud", "update": 10},
        {"description": "Uploading to Seafile", "update": 10},
        {"description": "Uploading to Filebase", "update": 10},
        {"description": "Creating Todoist task", "update": 10},
        {"description": "Creating CalDAV event", "update": 10},
        {"description": "Sending email with attachment", "update": 10},
    ]

    with tqdm(total=130, desc=f"{Fore.GREEN}Bitwarden Backup", ncols=100, bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.BLUE, Fore.RESET)) as pbar:
        try:
            bw_export_proc = subprocess.Popen(["/usr/local/bin/bw", "export", "--raw", "--format", "json", "--session", bw_session], stdout=subprocess.PIPE)
            data, _ = bw_export_proc.communicate()
            if data is None:
                logging.error(f"{Fore.RED}Failed to export Bitwarden data")
                return
            encrypted_data = encrypt(data, secrets["ENCRYPTION_PASSWORD"])
            pbar.update(progress_stages[0]["update"])

            attachments = []
            try:
                attachments_proc = subprocess.Popen(["/usr/local/bin/bw", "list", "items", "--session", bw_session], stdout=subprocess.PIPE)
                items_data, _ = attachments_proc.communicate()
                if not items_data.strip():
                    logging.error(f"{Fore.RED}No items retrieved from Bitwarden.")
                    raise Exception("No items retrieved from Bitwarden.")
                items = json.loads(items_data)
                with open(attachments_info_filepath, "w") as f:
                    for item in items:
                        if "attachments" in item:
                            for attachment in item["attachments"]:
                                attachment_id = attachment["id"]
                                attachment_name = attachment["fileName"]
                                attachment_path = os.path.join(env_vars["BACKUP_DIR"], attachment_name)
                                download_proc = subprocess.Popen(["/usr/local/bin/bw", "get", "attachment", attachment_id, "--itemid", item["id"], "--raw", "--session", bw_session], stdout=subprocess.PIPE)
                                attachment_data, _ = download_proc.communicate()
                                if not attachment_data.strip():
                                    logging.error(f"{Fore.RED}Attachment {attachment_name} is empty.")
                                    continue
                                attachments.append((attachment_name, attachment_data))
                                logging.info(f"{Fore.GREEN}Attachment {attachment_name} retrieved")
                                f.write(f"Item: {item['name']},Attachment: {attachment_name},itemID:{item['id']}\n")
                pbar.update(progress_stages[1]["update"])
            except Exception as e:
                logging.error(f"{Fore.RED}Error exporting Bitwarden attachments: {e}")
                return

            with pyzipper.AESZipFile(attachments_zip_filepath, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(secrets["ZIP_ATTACHMENT_PASSWORD"].encode())
                for attachment_name, attachment_data in attachments:
                    zf.writestr(os.path.join("attachments", attachment_name), attachment_data)
                zf.write(attachments_info_filepath, os.path.basename(attachments_info_filepath))
            pbar.update(progress_stages[2]["update"])

            with pyzipper.AESZipFile(zip_filepath, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(secrets["ZIP_PASSWORD"].encode())
                zf.writestr(f"bw-backup_{timestamp}.json", encrypted_data)
                zf.write(attachments_zip_filepath, os.path.basename(attachments_zip_filepath))
            logging.info(f"{Fore.GREEN}ZIP file created at {zip_filepath}")

            zip_hash = calculate_hash(zip_filepath)
            with open(f"{zip_filepath}.hash", "w") as hash_file:
                hash_file.write(zip_hash)
            logging.info(f"{Fore.GREEN}Hash for ZIP file: {zip_hash}")
            pbar.update(progress_stages[2]["update"])

            notification_message = f"ZIP File Encryption and Storage in Local Path {zip_filepath} ✅📚🔐🖥️"
            send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
            send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
            send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
            pbar.update(progress_stages[2]["update"])

            if os.path.exists(attachments_zip_filepath):
                os.remove(attachments_zip_filepath)
            if os.path.exists(attachments_info_filepath):
                os.remove(attachments_info_filepath)
        except Exception as e:
            logging.error(f"{Fore.RED}Error creating ZIP file: {e}")
            return

        if all([secrets.get("DROPBOX_ACCESS_TOKEN"), secrets.get("DROPBOX_REFRESH_TOKEN"), secrets.get("DROPBOX_APP_KEY"), secrets.get("DROPBOX_APP_SECRET")]):
            try:
                dropbox_access_token = refresh_dropbox_token(secrets["DROPBOX_REFRESH_TOKEN"], secrets["DROPBOX_APP_KEY"], secrets["DROPBOX_APP_SECRET"])
                dbx = dropbox.Dropbox(dropbox_access_token)
                folder_path = '/bitwarden-drive-backup'
                try:
                    dbx.files_get_metadata(folder_path)
                except dropbox.exceptions.ApiError as e:
                    if isinstance(e.error, dropbox.files.GetMetadataError) and e.error.is_path() and e.error.get_path().is_not_found():
                        dbx.files_create_folder_v2(folder_path)
                with open(zip_filepath, "rb") as f:
                    dbx.files_upload(f.read(), f"{folder_path}/bw-backup_{timestamp}.zip")
                logging.info(f"{Fore.GREEN}ZIP file uploaded to Dropbox")
                notification_message = f"ZIP File Uploaded and Encrypted to Dropbox Successfully ✅📚🔐☁️"
                send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
                send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
                send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
                pbar.update(progress_stages[3]["update"])
            except Exception as e:
                logging.error(f"{Fore.RED}Error uploading to Dropbox: {e}")
                notification_message = f"Error uploading to Dropbox: {e}"
        else:
            logging.warning(f"{Fore.YELLOW}Dropbox is not configured. Uploads to Dropbox will be skipped.")
            pbar.update(progress_stages[3]["update"])

        if drive_service and env_vars.get("GOOGLE_FOLDER_ID"):
            try:
                backup_folder_id = create_folder_if_not_exists(drive_service, "bitwarden-drive-backup", parent_folder_id=env_vars["GOOGLE_FOLDER_ID"])
                upload_file_to_drive(drive_service, zip_filepath, backup_folder_id)
                logging.info(f"{Fore.GREEN}ZIP file uploaded to Google Drive")
                notification_message = f"ZIP File Uploaded and Encrypted to Google Drive Successfully ✅📚🔐☁️"
                send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
                send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
                send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
                pbar.update(progress_stages[4]["update"])
            except Exception as e:
                logging.error(f"{Fore.RED}Error uploading to Google Drive: {e}")
                notification_message = f"Error uploading to Google Drive: {e}"
        else:
            logging.warning(f"{Fore.YELLOW}Google Drive is not configured. Uploads to Google Drive will be skipped.")
            pbar.update(progress_stages[4]["update"])

        if secrets.get("PCLOUD_USERNAME") and secrets.get("PCLOUD_PASSWORD"):
            try:
                upload_file_to_pcloud(zip_filepath, "bitwarden-drive-backup", secrets["PCLOUD_USERNAME"], secrets["PCLOUD_PASSWORD"])
                logging.info(f"{Fore.GREEN}ZIP file uploaded to pCloud")
                notification_message = f"ZIP File Uploaded and Encrypted to pCloud Successfully ✅📚🔐☁️"
                send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
                send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
                send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
                pbar.update(progress_stages[5]["update"])
            except Exception as e:
                logging.error(f"{Fore.RED}Error uploading to pCloud: {e}")
                notification_message = f"Error uploading to pCloud: {e}"
        else:
            logging.warning(f"{Fore.YELLOW}pCloud is not configured. Uploads to pCloud will be skipped.")
            pbar.update(progress_stages[5]["update"])

        if secrets.get("MEGA_EMAIL") and secrets.get("MEGA_PASSWORD"):
            try:
                upload_file_to_mega(zip_filepath, secrets["MEGA_EMAIL"], secrets["MEGA_PASSWORD"])
                logging.info(f"{Fore.GREEN}ZIP file uploaded to Mega")
                notification_message = f"ZIP File Uploaded and Encrypted to Mega Successfully ✅📚🔐☁️"
                send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
                send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
                send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
                pbar.update(progress_stages[6]["update"])
            except Exception as e:
                logging.error(f"{Fore.RED}Error uploading to Mega: {e}")
                notification_message = f"Error uploading to Mega: {e}"
        else:
            logging.warning(f"{Fore.YELLOW}Mega is not configured. Uploads to Mega will be skipped.")
            pbar.update(progress_stages[6]["update"])

        if all([secrets.get("NEXTCLOUD_URL"), secrets.get("NEXTCLOUD_USERNAME"), secrets.get("NEXTCLOUD_PASSWORD")]):
            try:
                upload_file_to_nextcloud(zip_filepath, secrets["NEXTCLOUD_URL"], secrets["NEXTCLOUD_USERNAME"], secrets["NEXTCLOUD_PASSWORD"])
                logging.info(f"{Fore.GREEN}ZIP file uploaded to Nextcloud")
                notification_message = f"ZIP File Uploaded and Encrypted to Nextcloud Successfully ✅📚🔐☁️"
                send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
                send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
                send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
                pbar.update(progress_stages[7]["update"])
            except Exception as e:
                logging.error(f"{Fore.RED}Error uploading to Nextcloud: {e}")
                notification_message = f"Error uploading to Nextcloud: {e}"
        else:
            logging.warning(f"{Fore.YELLOW}Nextcloud is not configured. Uploads to Nextcloud will be skipped.")
            pbar.update(progress_stages[7]["update"])

        if all([secrets.get("SEAFILE_SERVER_URL"), secrets.get("SEAFILE_USERNAME"), secrets.get("SEAFILE_PASSWORD")]):
            try:
                upload_file_to_seafile(zip_filepath, secrets["SEAFILE_SERVER_URL"], secrets["SEAFILE_USERNAME"], secrets["SEAFILE_PASSWORD"])
                logging.info(f"{Fore.GREEN}ZIP file uploaded to Seafile")
                notification_message = f"ZIP File Uploaded and Encrypted to Seafile Successfully ✅📚🔐☁️"
                send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
                send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
                send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
                pbar.update(progress_stages[8]["update"])
            except Exception as e:
                logging.error(f"{Fore.RED}Error uploading to Seafile: {e}")
                notification_message = f"Error uploading to Seafile: {e}"
        else:
            logging.warning(f"{Fore.YELLOW}Seafile is not configured. Uploads to Seafile will be skipped.")
            pbar.update(progress_stages[8]["update"])

        if all([secrets.get("FILEBASE_ACCESS_KEY"), secrets.get("FILEBASE_SECRET_KEY")]):
            try:
                upload_file_to_filebase(zip_filepath, secrets["FILEBASE_ACCESS_KEY"], secrets["FILEBASE_SECRET_KEY"], f"bw-backup_{timestamp}.zip")
                logging.info(f"{Fore.GREEN}ZIP file uploaded to Filebase")
                notification_message = f"ZIP File Uploaded and Encrypted to Filebase Successfully ✅📚🔐☁️"
                send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
                send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
                send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
                pbar.update(progress_stages[9]["update"])
            except Exception as e:
                logging.error(f"{Fore.RED}Error uploading to Filebase: {e}")
                notification_message = f"Error uploading to Filebase: {e}"
        else:
            logging.warning(f"{Fore.YELLOW}Filebase is not configured. Uploads to Filebase will be skipped.")
            pbar.update(progress_stages[9]["update"])

        if secrets.get("TODOIST_TOKEN"):
            try:
                project_id = get_or_create_todoist_project(secrets["TODOIST_TOKEN"], "Bitwarden Drive Backup")
                headers = {"Authorization": f"Bearer {secrets['TODOIST_TOKEN']}", "Content-Type": "application/json"}
                now = arrow.utcnow().to(TIMEZONE)
                timestamp_24h = now.format("YYYY-MM-DD HH:mm:ss")
                task_name = f"Bitwarden Backup {timestamp_24h}"
                task_date = now.format("YYYY-MM-DD HH:mm")
                payload = {
                    "content": task_name,
                    "project_id": project_id,
                    "due_date": task_date,
                    "priority": 2,
                    "labels": ["Bitwarden Backup"],
                    "description": "The performed backup is handled by Lazywarden"
                }
                response = requests.post("https://api.todoist.com/rest/v2/tasks", headers=headers, json=payload, timeout=10)
                if response.status_code == 200:
                    logging.info(f"{Fore.GREEN}Task '{task_name}' Created in the 'bitwarden-drive-backup' Project ☑️📚📁")
                    notification_message = f"Task '{task_name}' Created in the 'bitwarden-drive-backup' Project ☑️📚📁"
                    send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
                    send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
                    send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
                    pbar.update(progress_stages[10]["update"])
                else:
                    logging.error(f"{Fore.RED}Failed to create Todoist task")
                    notification_message = f"Failed to create Todoist task"
            except Exception as e:
                logging.error(f"{Fore.RED}Error creating Todoist task: {e}")
                notification_message = f"Error creating Todoist task: {e}"
        else:
            logging.warning(f"{Fore.YELLOW}Todoist is not configured. Task creation in Todoist will be skipped.")
            pbar.update(progress_stages[10]["update"])

        if all([secrets.get("CALDAV_URL"), secrets.get("CALDAV_USERNAME"), secrets.get("CALDAV_PASSWORD")]):
            try:
                start = arrow.utcnow()
                end = start.shift(hours=1)
                create_caldav_event(
                    summary="Bitwarden Backup",
                    description=f"Backup Created on Date {start.format('YYYY-MM-DD')}",
                    location="The Performed Backup is Handled by Lazywarden",
                    start=start,
                    end=end,
                    caldav_url=secrets["CALDAV_URL"],
                    caldav_username=secrets["CALDAV_USERNAME"],
                    caldav_password=secrets["CALDAV_PASSWORD"]
                )
                notification_message = f"CalDAV Event Successfully Created on Bitwarden New Backup Calendar ✅📅"
                send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
                send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
                send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
                logging.info(notification_message)
                pbar.update(progress_stages[11]["update"])
            except Exception as e:
                logging.error(f"{Fore.RED}Error creating CalDAV event: {e}")
                notification_message = f"Error creating CalDAV event: {e}"
        else:
            logging.warning(f"{Fore.YELLOW}CalDAV is not configured. Event creation in CalDAV will be skipped.")
            pbar.update(progress_stages[11]["update"])

        if all([env_vars.get("SMTP_SERVER"), env_vars.get("SMTP_PORT"), env_vars.get("SMTP_USERNAME"), env_vars.get("SMTP_PASSWORD"), env_vars.get("EMAIL_RECIPIENT"), env_vars.get("SENDER_EMAIL")]):
            try:
                send_email_with_attachment(env_vars["SMTP_SERVER"], env_vars["SMTP_PORT"], env_vars["SMTP_USERNAME"], env_vars["SMTP_PASSWORD"], env_vars["SENDER_EMAIL"], env_vars["EMAIL_RECIPIENT"], 
                                        "Bitwarden Backup", f"", zip_filepath)
                logging.info(f"{Fore.GREEN}Email with attachment sent successfully")
                notification_message = f"ZIP File Sent and Encrypted to Email Successfully ✅📚🔐📧"
                send_telegram_notification(notification_message, env_vars["TELEGRAM_TOKEN"], env_vars["TELEGRAM_CHAT_ID"])
                send_discord_notification(notification_message, env_vars["DISCORD_WEBHOOK_URL"])
                send_slack_notification(notification_message, env_vars["SLACK_WEBHOOK_URL"])
                pbar.update(progress_stages[12]["update"])
            except Exception as e:
                logging.error(f"{Fore.RED}Error sending email with attachment: {e}")
                notification_message = f"Error sending email with attachment: {e}"
        else:
            logging.warning(f"{Fore.YELLOW}SMTP is not configured. Sending emails will be skipped.")
            pbar.update(progress_stages[12]["update"])

if __name__ == "__main__":
    env_vars = load_environment_variables()
    configure_logging()

    try:
        bw_client = BitwardenClient(client_settings_from_dict({
            "apiUrl": env_vars["API_URL"],
            "identityUrl": env_vars["IDENTITY_URL"],
            "deviceType": DeviceType.SDK,
            "userAgent": "Python",
        }))
        bw_client.access_token_login(env_vars["ACCESS_TOKEN"])

        secrets = retrieve_secrets(bw_client)
        backup_bitwarden(env_vars, secrets, drive_service=None)
    except Exception as e:
        logging.error(f"Error during Bitwarden backup: {e}")
