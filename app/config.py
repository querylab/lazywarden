import logging
import os
from dotenv import load_dotenv

def load_environment_variables():
    load_dotenv()
    required_vars = [
        "API_URL", "IDENTITY_URL", "ORGANIZATION_ID", "ACCESS_TOKEN",
        "BACKUP_DIR"
    ]
    optional_vars = [
        "TELEGRAM_TOKEN", "TELEGRAM_CHAT_ID", "DISCORD_WEBHOOK_URL", "SLACK_WEBHOOK_URL",
        "GOOGLE_SERVICE_ACCOUNT_FILE", "GOOGLE_FOLDER_ID", "SMTP_SERVER",
        "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "EMAIL_RECIPIENT", "SENDER_EMAIL"
    ]
    env_vars = {var: os.getenv(var) for var in required_vars + optional_vars}
    
    missing_vars = [var for var in required_vars if not env_vars[var]]
    if missing_vars:
        raise ValueError(f"One or more required environment variables are not set: {', '.join(missing_vars)}")
    
    for var in optional_vars:
        if not env_vars[var]:
            logging.warning(f"Optional environment variable {var} is not set. Some functionality may be disabled.")
    
    return env_vars

def configure_logging():
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=log_format)

# Call the function to configure logging
configure_logging()
