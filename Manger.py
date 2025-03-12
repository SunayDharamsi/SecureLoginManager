import os
import json
import bcrypt
import random
import base64
from email.mime.text import MIMEText
from email.message import EmailMessage

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# -- Constants --
USERS_FILE = 'users.json'  # File where user credentials are stored
SCOPES = ['https://www.googleapis.com/auth/gmail.send']  # Gmail API scope for sending emails

# ==============================
# USER ACCOUNT STORAGE FUNCTIONS
# ==============================

def load_users():
    """
    Load user data from the local JSON file.
    If the file does not exist, return an empty dictionary.
    """
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    """
    Save user data (email & hashed passwords) to the JSON file.
    """
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

# ==============================
# PASSWORD HASHING FUNCTIONS
# ==============================

def hash_password(password):
    """
    Hash and salt a password using bcrypt.
    Returns the hashed password as a string.
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password, hashed):
    """
    Verify if a provided password matches the stored bcrypt hash.
    Returns True if the password is correct, False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed.encode())

# ==============================
# OTP GENERATION FUNCTION
# ==============================

def generate_otp():
    """
    Generate a 6-digit OTP (One-Time Password) for authentication.
    """
    return str(random.randint(100000, 999999))

# ==============================
# GMAIL AUTHENTICATION & OTP SENDING
# ==============================

def authenticate_gmail():
    """
    Authenticate with Google using OAuth 2.0.
    - If a valid token.json exists, reuse it.
    - If expired, refresh the token.
    - If no token, start the OAuth flow via browser sign-in.
    
    Returns a Gmail API service instance.
    """
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=8080)  # 🔐 Fixed port to match Google Cloud redirect URI
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    return build('gmail', 'v1', credentials=creds)

def send_otp_email(recipient_email, otp_code):
    """
    Send an OTP email using Gmail API.
    
    Arguments:
    - recipient_email: The user's email address
    - otp_code: The generated OTP to be sent
    """
    service = authenticate_gmail()
    
    # Create email message
    message = MIMEText(f'Your OTP is: {otp_code}')
    message['to'] = recipient_email
    message['subject'] = 'Login OTP'

    # Encode email message
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    body = {'raw': raw}

    # Send the email via Gmail API
    try:
        service.users().messages().send(userId="me", body=body).execute()
        print("✅ OTP email sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send OTP: {e}")

# ==============================
# ACCOUNT CREATION FUNCTION
# ==============================

def create_account():
    """
    Register a new user by:
    - Prompting for an email and password
    - Hashing the password
    - Storing the credentials in users.json
    """
    users = load_users()
    email = input("Enter your email: ").strip()
    
    if email in users:
        print("⚠️ Account already exists.")
        return

    password = input("Create a password: ").strip()
    users[email] = hash_password(password)
    save_users(users)
    print("✅ Account created successfully!")

# ==============================
# LOGIN FUNCTION (WITH OTP)
# ==============================

def login():
    """
    Log in an existing user by:
    - Verifying their email and password
    - Sending a 6-digit OTP via email
    - Requiring OTP verification before granting access
    """
    users = load_users()
    email = input("Enter your email: ").strip()
    password = input("Enter your password: ").strip()

    if email not in users:
        print("❌ No account with that email.")
        return

    if verify_password(password, users[email]):
        otp = generate_otp()  # Generate OTP
        send_otp_email(email, otp)  # Send OTP via email
        entered_otp = input("Enter the OTP sent to your email: ").strip()

        if entered_otp == otp:
            print("🎉 Login successful!")
        else:
            print("❌ Incorrect OTP.")
    else:
        print("❌ Incorrect password.")

# ==============================
# MAIN MENU
# ==============================

def main():
    """
    Display a simple command-line menu for the user.
    """
    while True:
        print("\n==== Secure Login System with Gmail OTP ====")
        print("1. Create Account")
        print("2. Log In")
        print("3. Exit")
        choice = input("Select an option: ").strip()

        if choice == '1':
            create_account()
        elif choice == '2':
            login()
        elif choice == '3':
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice.")

# Run the script
if __name__ == '__main__':
    main()
