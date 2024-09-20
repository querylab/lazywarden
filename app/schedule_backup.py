import calendar, subprocess, os, logging, smtplib, arrow, requests
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from colorama import init, Fore, Style
from requests.exceptions import RequestException, Timeout
from dotenv import load_dotenv
from bitwarden_client import setup_bitwarden_client, authenticate_bitwarden_client
from secrets_manager import retrieve_secrets
from caldav import DAVClient, Calendar, Event
from icalendar import Calendar as iCalendar, Event as iEvent
from terminaltexteffects.effects import effect_rain, effect_beams, effect_wipe
import time
import os
import sys

# Load environment variables from .env file
load_dotenv()

# Initialize colorama for colored terminal output
init(autoreset=True)

# Constants
CALENDAR_NAME = "Scheduled Bitwarden Backup"
TODOIST_PROJECT_NAME = "Scheduled Bitwarden Backup"
TODOIST_TASK_PRIORITY = 4
TASK_LABELS = ["Bitwarden Backup"]

# Load TIMEZONE from environment variables
TIMEZONE = os.getenv('TIMEZONE')

##-------------Interactive-------------
def clear_screen():
    print("\033c", end="")  # Clear the terminal
    
def display_ascii_art():
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
    print("\033c", end="")  # Clear the terminal

    welcome_text = "WELCOME TO LAZYWARDEN"
    effect_welcome = effect_rain.Rain(welcome_text)
    effect_welcome.effect_config.final_gradient_frames = 1
    
    with effect_welcome.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_welcome:
            terminal.print(frame)
            time.sleep(0.06)  # Ajuste de velocidad de la animación
            print()

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

    press_enter_text = "Starting Bitwarden Vault Backup"
    effect_press_enter = effect_rain.Rain(press_enter_text)
    effect_press_enter.effect_config.final_gradient_frames = 1
    
    with effect_press_enter.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_press_enter:
            terminal.print(frame)
            time.sleep(0.05)  # Ajuste de velocidad de la animación
            print()
            print()
            
            
def display_backup_frequency_options():
    """
    Display backup frequency options using Rain effect and get user choice.

    Returns:
        datetime: Scheduled time based on user choice.
    """
    options_text = "Choose the frequency of the backups:\n1. Daily\n2. Weekly\n3. Monthly\n4. Yearly"
    effect_options = effect_wipe.Wipe(options_text)
    effect_options.effect_config.final_gradient_frames = 1
    
    with effect_options.terminal_output(end_symbol=" ") as terminal:
        for frame in effect_options:
            terminal.print(frame)
            time.sleep(0.1)
            print()
            print()

    # Get user choice for backup frequency
    while True:
        try:
            choice = int(input("Enter your choice (1-4): "))
            if choice < 1 or choice > 4:
                raise ValueError("Choice must be between 1 and 4.")
            break
        except ValueError as e:
            print(f"{Fore.RED}{e}{Fore.RESET}. Please try again.")

    now = datetime.now()

    # Determine the scheduled time based on user choice
    if choice == 1:  # Daily
        hour, minute = get_user_input_without_calendar()
        scheduled_time = datetime(now.year, now.month, now.day, hour, minute)
    elif choice == 2:  # Weekly
        day, hour, minute = get_user_input_weekly()
        scheduled_time = datetime(now.year, now.month, day, hour, minute)
    elif choice == 3:  # Monthly
        month, day, hour, minute = get_user_input_month()
        scheduled_time = datetime(now.year, month, day, hour, minute)
    elif choice == 4:  # Yearly
        while True:
            try:
                year = int(input("Enter the year (2024-2030): "))
                if year < 2024 or year > 2030:
                    raise ValueError("Year must be between 2024 and 2030.")
                month, day, hour, minute = get_user_input_month()
                scheduled_time = datetime(year, month, day, hour, minute)
                break
            except ValueError as e:
                print(f"{Fore.RED}{e}{Fore.RESET}. Please try again.")
    
    return scheduled_time

def send_email_notification(smtp_server, smtp_port, smtp_username, smtp_password, sender, recipient, subject, body):
    logging.info(f"SMTP_SERVER: {smtp_server}")
    logging.info(f"SMTP_PORT: {smtp_port}")
    logging.info(f"SMTP_USERNAME: {smtp_username}")
    logging.info(f"SMTP_PASSWORD: {smtp_password}")
    logging.info(f"SENDER_EMAIL: {sender}")
    logging.info(f"RECEIVER_EMAIL: {recipient}")

    if not all([smtp_server, smtp_port, smtp_username, smtp_password, sender, recipient]):
        logging.error("Missing one or more email configuration variables.")
        return

    message = MIMEMultipart('mixed')
    message['Subject'] = subject
    message['From'] = sender
    message['To'] = recipient

    html_body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: Arial, sans-serif;
                color: #333;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                background-color: #f4f4f9;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                background-color: #fff;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .header {{
                text-align: center;
                padding-bottom: 20px;
                border-bottom: 1px solid #e0e0e0;
            }}
            .header img {{
                max-width: 100px;
                height: auto;
            }}
            .content {{
                text-align: center;
                padding: 20px 0;
            }}
            .footer {{
                text-align: center;
                font-size: 12px;
                color: #777;
                padding-top: 20px;
                border-top: 1px solid #e0e0e0;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <img src="https://raw.githubusercontent.com/querylab/svg/main/lazylogo2.png" alt="Bitwarden Logo" style="width: 110px; height: auto; vertical-align: middle; margin-top: 10px;">
            </div>
            <div class="content">
                <p>Hello!</p>
                <p>Your <strong>Scheduled Bitwarden Backup</strong> backup has been processed.</p>
                <p>{body}</p>
                <p>Thank you for using our service.</p>
            </div>
            <div class="footer">
                <p>&copy; 2024 Lazywarden Backup Service. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """

    html_message = MIMEText(html_body, 'html')
    message.attach(html_message)

    try:
        mail_server = smtplib.SMTP(smtp_server, smtp_port)
        mail_server.ehlo()
        mail_server.starttls()
        mail_server.ehlo()
        mail_server.login(smtp_username, smtp_password)
        mail_server.sendmail(sender, recipient, message.as_string())
        mail_server.close()
        logging.info("Email sent successfully")
    except smtplib.SMTPConnectError as e:
        logging.error(f"Connection error: {e}")
    except smtplib.SMTPAuthenticationError as e:
        logging.error(f"Authentication error: {e}")
    except smtplib.SMTPException as e:
        logging.error(f"SMTP error: {e}")
    except Exception as e:
        logging.error(f"Error sending email: {e}")

def notify_backup_start(scheduled_time):
    subject = "Backup Job Started"
    body = f"Your Bitwarden backup job has started. Scheduled time: {scheduled_time}."
    send_email_notification(
        smtp_server=os.getenv("SMTP_SERVER"),
        smtp_port=int(os.getenv("SMTP_PORT")),
        smtp_username=os.getenv("SMTP_USERNAME"),
        smtp_password=os.getenv("SMTP_PASSWORD"),
        sender=os.getenv("SENDER_EMAIL"),
        recipient=os.getenv("EMAIL_RECIPIENT"),
        subject=subject,
        body=body
    )

def closing_message(scheduled_time):
    print(f"\n{Fore.GREEN}Backup job scheduled successfully!{Fore.RESET}")
    print(f"{Fore.BLUE}{'='*50}\n")
    print(f"{Fore.YELLOW}Creating schedule entries...\n")
    for i in range(3):
        print(f"{Fore.YELLOW}🔑", end="", flush=True)
        time.sleep(0.5)
    print(f"{Fore.YELLOW}🔒{Fore.RESET}\n")
    print(f"{Fore.GREEN}Your backup is scheduled for {scheduled_time}!{Fore.RESET}\n")

def display_calendar(year, month):
    try:
        print(calendar.month(year, month))
    except calendar.IllegalMonthError:
        print(f"{Fore.RED}Invalid month. Please enter a value between 1 and 12.{Fore.RESET}")

def get_user_input_with_calendar():
    while True:
        try:
            year = int(input("Enter the year (2024-2030): "))
            if year < 2024 or year > 2030:
                raise ValueError("Year must be between 2024 and 2030.")
            month = int(input("Enter the month (1-12): "))
            if month < 1 or month > 12:
                raise ValueError("Month must be between 1 and 12.")
            display_calendar(year, month)
            day = int(input("Enter the day (1-31): "))
            if day < 1 or day > 31:
                raise ValueError("Day must be between 1 and 31.")
            hour = int(input("Enter the hour (0-23): "))
            if hour < 0 or hour > 23:
                raise ValueError("Hour must be between 0 and 23.")
            minute = int(input("Enter the minute (0-59): "))
            if minute < 0 or minute > 59:
                raise ValueError("Minute must be between 0 and 59.")
            return year, month, day, hour, minute
        except ValueError as e:
            print(f"{Fore.RED}{e}{Fore.RESET}. Please try again.")

def get_user_input_month():
    while True:
        try:
            month = int(input("Enter the month (1-12): "))
            if month < 1 or month > 12:
                raise ValueError("Month must be between 1 and 12.")
            display_calendar(datetime.now().year, month)
            day = int(input("Enter the day (1-31): "))
            if day < 1 or day > 31:
                raise ValueError("Day must be between 1 and 31.")
            hour = int(input("Enter the hour (0-23): "))
            if hour < 0 or hour > 23:
                raise ValueError("Hour must be between 0 and 23.")
            minute = int(input("Enter the minute (0-59): "))
            if minute < 0 or minute > 59:
                raise ValueError("Minute must be between 0 and 59.")
            return month, day, hour, minute
        except ValueError as e:
            print(f"{Fore.RED}{e}{Fore.RESET}. Please try again.")

def get_user_input_weekly():
    while True:
        try:
            today = datetime.today()
            display_calendar(today.year, today.month)
            day = int(input("Enter the day (1-31): "))
            if day < 1 or day > 31:
                raise ValueError("Day must be between 1 and 31.")
            hour = int(input("Enter the hour (0-23): "))
            if hour < 0 or hour > 23:
                raise ValueError("Hour must be between 0 and 23.")
            minute = int(input("Enter the minute (0-59): "))
            if minute < 0 or minute > 59:
                raise ValueError("Minute must be between 0 and 59.")
            
            selected_date = datetime(today.year, today.month, day, hour, minute)
            # If the selected date is in the past for this week, schedule for next week
            if selected_date < today:
                selected_date += timedelta(weeks=1)
            
            return selected_date.day, selected_date.hour, selected_date.minute
        except ValueError as e:
            print(f"{Fore.RED}{e}{Fore.RESET}. Please try again.")

def get_user_input_without_calendar():
    while True:
        try:
            hour = int(input("Enter the hour (0-23): "))
            if hour < 0 or hour > 23:
                raise ValueError("Hour must be between 0 and 23.")
            minute = int(input("Enter the minute (0-59): "))
            if minute < 0 or minute > 59:
                raise ValueError("Minute must be between 0 and 59.")
            return hour, minute
        except ValueError as e:
            print(f"{Fore.RED}{e}{Fore.RESET}. Please try again.")



def create_backup_job_with_cron(year, month, day, hour, minute):
    job_time = f"{minute} {hour} {day} {month} *"
    command = "root /root/lazywarden/venv/bin/python3 /root/lazywarden/app/main.py >> /var/log/lazywarden-cron.log 2>&1"
    cron_job = f"{job_time} {command}\n"

    try:
        # Abre el archivo cron de lazywarden y añade la nueva entrada sin sobrescribir
        with open("/etc/cron.d/lazywarden-cron", "a") as file:
            file.write(cron_job)

        # Asegúrate de que las entradas de cron tengan los permisos correctos
        subprocess.run(["chmod", "0644", "/etc/cron.d/lazywarden-cron"])

        # Reinicia el servicio cron para que reconozca la nueva tarea
        subprocess.run(["service", "cron", "reload"])

        print(f"{Fore.GREEN}Backup job scheduled to run at {job_time}.{Fore.RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Failed to schedule backup job: {e}{Fore.RESET}")
    return job_time




def create_caldav_event(summary, description, location, scheduled_time, caldav_url, caldav_username, caldav_password):
    try:
        client = DAVClient(caldav_url, username=caldav_username, password=caldav_password)
        principal = client.principal()
        calendars = principal.calendars()
        if not calendars:
            raise Exception("No calendars found for this user")
        calendar_name = "Scheduled Bitwarden Backup"
        calendar = next((cal for cal in calendars if cal.name == calendar_name), None)
        if not calendar:
            calendar = principal.make_calendar(calendar_name)
            logging.info(f"{Fore.GREEN}Calendar '{calendar_name}' created.")
        cal = iCalendar()
        event = iEvent()
        event.add('summary', summary)
        event.add('description', description)
        event.add('location', location)
        event.add('dtstart', scheduled_time)
        event.add('dtend', scheduled_time + timedelta(hours=1))  # Assuming the event lasts 1 hour
        event.add('dtstamp', arrow.utcnow().datetime)
        event['uid'] = f"{arrow.utcnow().format('YYYYMMDDTHHmmss')}@yourdomain.com"
        cal.add_component(event)
        calendar.add_event(cal.to_ical().decode('utf-8'))
        logging.info(f"{Fore.GREEN}Event '{summary}' created in calendar '{calendar_name}' from {scheduled_time} to {scheduled_time + timedelta(hours=1)}")
    except RequestException as re:
        logging.error(f"{Fore.RED}Connection error: {re}")
        raise
    except Exception as e:
        logging.error(f"{Fore.RED}Error: {e}")
        raise

def get_or_create_todoist_project(todoist_token, project_name):
    headers = {"Authorization": f"Bearer {todoist_token}", "Content-Type": "application/json"}
    try:
        response = requests.get("https://api.todoist.com/rest/v2/projects", headers=headers, timeout=30)
        response.raise_for_status()
        projects = response.json()
        project = next((p for p in projects if p["name"] == project_name), None)
        if project:
            return project["id"]
        else:
            payload = {"name": project_name, "color": "red"}
            response = requests.post("https://api.todoist.com/rest/v2/projects", headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            project = response.json()
            return project["id"]
    except (RequestException, Timeout) as e:
        logging.error(f"{Fore.RED}Error fetching or creating Todoist project: {e}{Fore.RESET}")
        raise



def create_todoist_task(todoist_token, project_id, task_name, due_datetime):
    headers = {"Authorization": f"Bearer {todoist_token}", "Content-Type": "application/json"}
    task_date = due_datetime.format("YYYY-MM-DD HH:mm:ss")
    payload = {
        "content": task_name,
        "project_id": project_id,
        "due_datetime": task_date,
        "priority": TODOIST_TASK_PRIORITY,
        "labels": TASK_LABELS,
        "description": "The performed backup is handled by Lazywarden"
    }
    try:
        response = requests.post("https://api.todoist.com/rest/v2/tasks", headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        logging.info(f"{Fore.GREEN}Task '{task_name}' created in the 'Scheduled Time Backup' project ☑️📚📁")
    except (Timeout, RequestException) as e:
        logging.error(f"{Fore.RED}Error creating Todoist task: {e}{Fore.RESET}")
        raise



def main():
    """
    Main function to schedule the backup job.
    """
    interactive_message()

    # Display backup frequency options
    scheduled_time = display_backup_frequency_options()

        # Schedule the backup job
    create_backup_job_with_cron(scheduled_time.year, scheduled_time.month, scheduled_time.day, scheduled_time.hour, scheduled_time.minute)

    # Muestra un mensaje de cierre confirmando que el trabajo de respaldo ha sido programado
    closing_message(scheduled_time)

    # Retrieve required environment variables
    api_url = os.getenv("API_URL")
    identity_url = os.getenv("IDENTITY_URL")
    access_token = os.getenv("ACCESS_TOKEN")

    if not api_url or not identity_url or not access_token:
        print(f"{Fore.RED}Error: One or more required environment variables are not set. Please check your .env file.{Fore.RESET}")
        return

    # Setup and authenticate Bitwarden client
    bw_client = setup_bitwarden_client(api_url, identity_url)

    try:
        authenticate_bitwarden_client(bw_client, access_token)
    except Exception as e:
        print(f"{Fore.RED}Error during Bitwarden login: {e}{Fore.RESET}")
        return

    # Retrieve secrets for CalDAV and Todoist
    secrets = retrieve_secrets(bw_client)
    caldav_url = secrets.get("CALDAV_URL")
    caldav_username = secrets.get("CALDAV_USERNAME")
    caldav_password = secrets.get("CALDAV_PASSWORD")
    todoist_token = secrets.get("TODOIST_TOKEN")

    # Create CalDAV event if credentials are available
    if caldav_url and caldav_username and caldav_password:
        try:
            start_time = arrow.get(scheduled_time)
            end_time = start_time.shift(hours=1)
            create_caldav_event(
                summary="Scheduled Bitwarden Backup",
                description=f"Scheduled Time for Bitwarden backup: {start_time.format('YYYY-MM-DD HH:mm:ss')}",
                location="The Performed Backup is Handled by Lazywarden",
                scheduled_time=start_time.datetime,
                caldav_url=caldav_url,
                caldav_username=caldav_username,
                caldav_password=caldav_password
            )
        except Exception as e:
            logging.error(f"{Fore.RED}Error creating CalDAV event: {e}")
            print(f"{Fore.RED}Error creating CalDAV event: {e}{Fore.RESET}")
    else:
        logging.warning(f"{Fore.YELLOW}CalDAV is not configured. Event creation in CalDAV will be skipped.{Fore.RESET}")
        print(f"{Fore.YELLOW}CalDAV is not configured. Event creation in CalDAV will be skipped.{Fore.RESET}")

    # Create Todoist task if token is available
    if todoist_token:
        try:
            project_id = get_or_create_todoist_project(todoist_token, TODOIST_PROJECT_NAME)
            task_name = f"Scheduled Start in {start_time.format('YYYY-MM-DD HH:mm:ss')}"
            create_todoist_task(todoist_token, project_id, task_name, start_time)
        except Exception as e:
            logging.error(f"{Fore.RED}Error creating Todoist task: {e}")
            print(f"{Fore.RED}Error creating Todoist task: {e}{Fore.RESET}")
    else:
        logging.warning(f"{Fore.YELLOW}Todoist is not configured. Task creation in Todoist will be skipped.{Fore.RESET}")
        print(f"{Fore.YELLOW}Todoist is not configured. Task creation in Todoist will be skipped.{Fore.RESET}")


    # Notify backup start if email configuration is available
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    sender_email = os.getenv("SENDER_EMAIL")
    email_recipient = os.getenv("EMAIL_RECIPIENT")

    if smtp_server and smtp_port and smtp_username and smtp_password and sender_email and email_recipient:
        notify_backup_start(scheduled_time)
    else:
        logging.warning(f"{Fore.YELLOW}Email notification is not configured. Email notification will be skipped.{Fore.RESET}")
        print(f"{Fore.YELLOW}Email notification is not configured. Email notification will be skipped.{Fore.RESET}")

  


if __name__ == "__main__":
    
    main()
    
