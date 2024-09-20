# notification.py

"""
This module contains functions to send notifications to various services.
"""
from imports import os, logging, requests, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


def send_telegram_notification(message, telegram_token, telegram_chat_id):
    """
    Sends a notification to Telegram.

    Args:
        message (str): Message to send.
        telegram_token (str): Telegram bot token.
        telegram_chat_id (str): Telegram chat ID.

    Raises:
        Exception: If an error occurs while sending the message.
    """
    if not telegram_token or not telegram_chat_id:
        logging.warning("Telegram is not configured. Notifications to Telegram will be skipped.")
        return
    try:
        import telebot
        bot = telebot.TeleBot(telegram_token)
        bot.send_message(telegram_chat_id, message)
        logging.info("Notification sent to Telegram")
    except Exception as e:
        logging.error(f"Error sending Telegram message: {e}")


def send_discord_notification(message, discord_webhook_url):
    """
    Sends a notification to Discord.

    Args:
        message (str): Message to send.
        discord_webhook_url (str): Discord webhook URL.

    Raises:
        Exception: If an error occurs while sending the message.
    """
    if not discord_webhook_url:
        logging.warning("Discord is not configured. Notifications to Discord will be skipped.")
        return
    data = {"content": message}
    try:
        response = requests.post(discord_webhook_url, json=data, timeout=10)
        if response.status_code == 204:
            logging.info("Notification sent to Discord")
        else:
            logging.error(f"Failed to send notification to Discord: {response.status_code}")
    except Exception as e:
        logging.error(f"Error sending notification to Discord: {e}")


def send_slack_notification(message, slack_webhook_url):
    """
    Sends a notification to Slack.

    Args:
        message (str): Message to send.
        slack_webhook_url (str): Slack webhook URL.

    Raises:
        Exception: If an error occurs while sending the message.
    """
    if not slack_webhook_url:
        logging.warning("Slack is not configured. Notifications to Slack will be skipped.")
        return
    data = {"text": message}
    try:
        response = requests.post(slack_webhook_url, json=data, timeout=10)
        if response.status_code == 200:
            logging.info("Notification sent to Slack")
        else:
            logging.error(f"Failed to send notification to Slack: {response.status_code}")
    except Exception as e:
        logging.error(f"Error sending notification to Slack: {e}")


def send_email_with_attachment(smtp_server, smtp_port, smtp_username, smtp_password, sender, recipient, subject, body, attachment_path):
    """
    Sends an email with an attachment.

    Args:
        smtp_server (str): SMTP server.
        smtp_port (int): SMTP port.
        smtp_username (str): SMTP username.
        smtp_password (str): SMTP password.
        sender (str): Sender email address.
        recipient (str): Recipient email address.
        subject (str): Email subject.
        body (str): Email body.
        attachment_path (str): Path to the attachment file.

    Raises:
        Exception: If an error occurs while sending the email.
    """
    if not all([smtp_server, smtp_port, smtp_username, smtp_password, sender, recipient]):
        logging.warning("SMTP is not fully configured. Email notifications will be skipped.")
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
            .logo-container {{
                display: flex;
                justify-content: center;
                align-items: center;
                gap: 10px;
            }}
            .header img {{
                max-width: 100px;
                height: auto;
            }}
            .content {{
                text-align: center;
                padding: 20px 0;
            }}
            .button {{
                display: inline-block;
                padding: 10px 20px;
                font-size: 16px;
                color: #ffffff;
                background-color: #1d0142;
                border-radius: 5px;
                text-decoration: none;
                margin: 20px 0;
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
                <div class="logo-container">
                    <img src="https://raw.githubusercontent.com/querylab/svg/main/lazylogo2.png" alt="Bitwarden Logo">
                </div>
            </div>
            <div class="content">
                <p>Hi there!</p>
                <p>Your <strong>Bitwarden Backup</strong> Files are Ready and Encrypted 📧🔗📚🔐</p>
                <p><a href="cid:attachment" class="button">Download Backup</a></p>
                <p>{body}</p>
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

    with open(attachment_path, 'rb') as file:
        attachment = MIMEApplication(file.read(), Name=os.path.basename(attachment_path))
        attachment['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
        attachment.add_header('Content-ID', '<attachment>')
        message.attach(attachment)

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
