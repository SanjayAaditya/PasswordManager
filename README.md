# Password Manager Application

## Overview

This Password Manager application is designed to securely store and manage passwords. It uses Python, Tkinter for the GUI, and the cryptography library for encryption. The application supports adding, viewing, editing, and deleting password entries, all protected by a master password.

## Features

- **Secure Password Storage**: Utilizes Fernet encryption to securely store passwords.
- **Master Password Protection**: Ensures that only the user with the correct master password can access the stored data.
- **User-Friendly GUI**: Built with Tkinter for easy interaction.
- **Clipboard Functionality**: Copies passwords and usernames to the clipboard securely.
- **Backup and Restore**: Provides functionalities to backup and restore data to safeguard against data loss.

## Technologies Used

- **Python**
- **Tkinter**: For creating the graphical user interface.
- **cryptography**: For encrypting and decrypting data.
- **pyperclip**: For copying data to the clipboard.
- **base64** and **hashlib**: For key generation and encoding.
- **File I/O**: For storing and managing encrypted data in text files.
