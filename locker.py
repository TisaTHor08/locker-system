import tkinter as tk
from tkinter import messagebox
import os
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import threading
import time

class LockerApp:
    def __init__(self, root):
        self.root = root
        self.root.title('Folder Locker')
        self.root.geometry('400x200')
        self.attempt_count = 0
        self.MAX_ATTEMPTS = 1000
        self.auto_lock_timer = None
        self.setup_ui()

    def setup_ui(self):
        self.frame = tk.Frame(self.root)
        self.frame.pack(expand=True)

        self.password_label = tk.Label(self.frame, text='Enter Password:')
        self.password_label.pack(pady=10)

        self.password_entry = tk.Entry(self.frame, show='*')
        self.password_entry.pack(pady=5)

        if os.path.exists('vault.crypt'):
            self.decrypt_button = tk.Button(self.frame, text='Decrypt', command=self.decrypt_files)
            self.decrypt_button.pack(pady=10)
        else:
            self.encrypt_button = tk.Button(self.frame, text='Encrypt', command=self.encrypt_files)
            self.encrypt_button.pack(pady=10)

        self.close_button = tk.Button(self.frame, text='Close', command=self.close_app)
        self.close_button.pack(pady=10)

    def generate_key(self, password):
        salt = b'salt_123'  # In production, use a random salt and store it securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_files(self):
        if not self.password_entry.get():
            messagebox.showerror('Error', 'Please enter a password')
            return

        try:
            key = self.generate_key(self.password_entry.get())
            fernet = Fernet(key)
            files_data = {}

            for filename in os.listdir('.'):
                if filename not in ['locker.exe', 'locker.py', 'vault.crypt'] and os.path.isfile(filename):
                    with open(filename, 'rb') as file:
                        file_data = file.read()
                        encrypted_data = fernet.encrypt(file_data)
                        files_data[filename] = encrypted_data.decode('utf-8')
                    os.remove(filename)

            with open('vault.crypt', 'w') as vault:
                json.dump(files_data, vault)

            messagebox.showinfo('Success', 'Files encrypted successfully')
            self.start_auto_lock_timer()

        except Exception as e:
            messagebox.showerror('Error', f'Encryption failed: {str(e)}')

    def decrypt_files(self):
        if self.attempt_count >= self.MAX_ATTEMPTS:
            messagebox.showerror('Error', 'Maximum password attempts exceeded')
            return

        try:
            key = self.generate_key(self.password_entry.get())
            fernet = Fernet(key)

            with open('vault.crypt', 'r') as vault:
                files_data = json.load(vault)

            for filename, encrypted_data in files_data.items():
                try:
                    decrypted_data = fernet.decrypt(encrypted_data.encode('utf-8'))
                    with open(filename, 'wb') as file:
                        file.write(decrypted_data)
                except Exception:
                    self.attempt_count += 1
                    messagebox.showerror('Error', 'Incorrect password')
                    return

            os.remove('vault.crypt')
            messagebox.showinfo('Success', 'Files decrypted successfully')
            self.start_auto_lock_timer()

        except Exception as e:
            self.attempt_count += 1
            messagebox.showerror('Error', f'Decryption failed: {str(e)}')

    def start_auto_lock_timer(self):
        if self.auto_lock_timer:
            self.auto_lock_timer.cancel()
        self.auto_lock_timer = threading.Timer(1800, self.auto_lock)  # 30 minutes
        self.auto_lock_timer.start()

    def auto_lock(self):
        if not os.path.exists('vault.crypt'):
            self.encrypt_files()

    def close_app(self):
        if not os.path.exists('vault.crypt'):
            self.encrypt_files()
        self.root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = LockerApp(root)
    root.protocol('WM_DELETE_WINDOW', app.close_app)
    root.mainloop()