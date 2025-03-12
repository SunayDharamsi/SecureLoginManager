# 🔐 SecureLoginManager – Password Manager with 2FA

SecureLoginManager is a secure and user-friendly password manager built in Python that incorporates **Two-Factor Authentication (2FA)** to enhance login security. This project was created to explore secure credential storage, user authentication, and email-based verification, aligning with industry best practices in cybersecurity.

---

## 📌 Features

- 🔐 **Secure Credential Storage**  
  - Passwords are hashed and salted before storage using modern cryptographic methods to prevent brute-force and rainbow table attacks.

- 📧 **Two-Factor Authentication (2FA)**  
  - Sends a unique verification code to the user's registered email as a second layer of authentication during login.

- 🧠 **Simple, User-Friendly Interface**  
  - Command-line interface allows for easy account creation, login, and credential management.

- 🗂️ **Encrypted Vault**  
  - Stores usernames and passwords for various services, protected behind master credentials.

---

## 🛠️ Technologies Used

- **Python 3**
- **bcrypt** – for secure password hashing
- **smtplib** / **email** – for sending email-based 2FA codes
- **os**, **json**, **random**, and other built-in libraries

---

## 🚀 How It Works

1. **User Registration**:  
   Users create an account with a master username and password. The password is hashed and stored securely.

2. **Login Process**:  
   - User enters credentials  
   - A unique 6-digit code is generated and emailed to the user  
   - User must enter the code to gain access

3. **Password Vault**:  
   Once authenticated, users can add, retrieve, or manage stored credentials for different services.
