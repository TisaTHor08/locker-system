# Folder Locker

A secure Python application that allows you to encrypt and protect your folders with a password.

## Features

- Password-protected folder encryption
- Automatic file encryption after 30 minutes of inactivity
- Secure encryption using AES
- Maximum 1,000 password attempts
- Simple and intuitive graphical interface
- Preserves file integrity during encryption/decryption

## Installation

1. Install Python 3.x if not already installed
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```
3. Compile the application into an executable:
   ```
   pyinstaller --noconsole --onefile locker.py
   ```
   The executable will be created in the `dist` folder.

## Usage

1. Copy `locker.exe` to the folder you want to secure
2. Run `locker.exe`
3. For first-time use:
   - Enter a password
   - Click 'Encrypt' to secure your files
4. To access your files:
   - Enter the password
   - Click 'Decrypt' to restore your files
5. Files will automatically re-encrypt after 30 minutes or when closing the application

## Security Notes

- Keep your password safe - there's no way to recover encrypted files without it
- The application creates a `vault.crypt` file containing your encrypted data
- Original files are securely deleted after encryption
- Do not delete the `vault.crypt` file while files are encrypted