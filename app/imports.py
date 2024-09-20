"""
imports.py

This module contains all the necessary imports for the project.
"""

import os
import subprocess
import logging
from datetime import datetime
import requests
import stat
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import dropbox
import telebot
import boto3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import pcloud
import pyzipper
from mega import Mega
from tqdm import tqdm
import shlex
import pyotp
import pexpect
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import smtplib
from dotenv import load_dotenv
from bitwarden_sdk import BitwardenClient, DeviceType, client_settings_from_dict
from uuid import UUID
from argon2.low_level import hash_secret_raw, Type
import nextcloud_client
import hashlib
import shutil
import time
from requests.exceptions import RequestException
import arrow
from colorama import init, Fore, Style
from caldav import DAVClient
from icalendar import Calendar as iCalendar, Event as iEvent
import calendar
# Initialize colorama
init(autoreset=True)
