import os
import subprocess 
import sys
import shutil
import zipfile
import stat

def install_package(package):
    """
    Installs a Python package using pip.

    Args:
        package (str): The name of the package to install.
    """
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def install_apt_package(package):
    """
    Installs a package using apt-get.

    Args:
        package (str): The name of the package to install.
    """
    subprocess.check_call(["sudo", "apt", "install", "-y", package])

def check_and_install_pip():
    """
    Checks if pip is installed, and installs it if it is not.
    """
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"])
    except subprocess.CalledProcessError:
        print("pip is not installed. Installing pip...")
        install_apt_package("python3-pip")

def check_and_install_requests():
    """
    Checks if the requests module is installed, and installs it if it is not.

    Returns:
        module: The requests module.
    """
    try:
        import requests
    except ImportError:
        print("The 'requests' module is not installed. Installing requests...")
        install_package("requests")
        import requests  # Import requests after installation
    return requests

def download_and_extract_zip(url, extract_to='.'):
    """
    Downloads a ZIP file from the specified URL and extracts it.

    Args:
        url (str): The URL to download the ZIP file from.
        extract_to (str, optional): The directory to extract the ZIP file to. Defaults to the current directory.

    Raises:
        sys.exit: If there is an error downloading or extracting the ZIP file.
    """
    requests = check_and_install_requests()
    try:
        local_zip_file = 'bw.zip'
        print(f"Downloading Bitwarden CLI from {url}...")
        response = requests.get(url)
        response.raise_for_status()
        with open(local_zip_file, 'wb') as file:
            file.write(response.content)
        
        print("Extracting the ZIP file...")
        with zipfile.ZipFile(local_zip_file, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        
        print("Removing the ZIP file...")
        os.remove(local_zip_file)
    except requests.RequestException as e:
        print(f"Error downloading the file: {e}")
        sys.exit(1)
    except zipfile.BadZipFile as e:
        print(f"Error extracting the ZIP file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

def check_superuser():
    """
    Checks if the script is being run as a superuser (root).

    Raises:
        sys.exit: If the script is not run as a superuser.
    """
    if os.geteuid() != 0:
        print("This script must be run as a superuser (root).")
        sys.exit(1)

def main():
    """
    Main function to download, extract, and install the Bitwarden CLI.
    """
    check_superuser()
    check_and_install_pip()

    url = "https://github.com/bitwarden/clients/releases/download/cli-v2024.7.1/bw-linux-2024.7.1.zip"
    download_path = os.path.join(os.getcwd(), 'bw')
    final_path = "/usr/local/bin/bw"

    download_and_extract_zip(url, extract_to=os.getcwd())

    print("Granting execution permissions to the extracted file...")
    try:
        st = os.stat(download_path)
        os.chmod(download_path, st.st_mode | stat.S_IEXEC)
    except Exception as e:
        print(f"Error changing file permissions: {e}")
        sys.exit(1)

    print("Moving the executable to /usr/local/bin...")
    try:
        shutil.move(download_path, final_path)
        print(f"Bitwarden CLI has been moved to {final_path} and is ready to use.")
    except PermissionError:
        print("Error: You do not have permissions to move files to /usr/local/bin. Run the script as a superuser (sudo).")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while moving the file: {e}")
        sys.exit(1)

    if os.path.exists(final_path):
        print("Process completed successfully.")
    else:
        print("The process failed. Please check the permissions and try again.")

if __name__ == "__main__":
    main()
