import tkinter as tk
from tkinter import simpledialog, ttk
from cryptography.fernet import Fernet
import os
import base64
import hashlib
import pyperclip

# Function to generate a key from the provided password
def generate_key(password):
    password = password.encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(password).digest())
    return key

# Function to encrypt data using the provided key
def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data

# Function to decrypt data using the provided key
def decrypt_data(encrypted_data, key):
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
    return decrypted_data

# Function to save the master key to a file
def save_master_key(file_path, password):
    key = generate_key(password)
    with open(file_path, 'wb') as file:
        file.write(key)

# Function to load the master key from a file
def load_master_key(file_path):
    try:
        with open(file_path, 'rb') as file:
            key = file.read()
            return key
    except FileNotFoundError:
        return None

# Function to set the master key for the first time
def set_master_key(file_path):
    root.withdraw()
    master_password = simpledialog.askstring("Password Manager", "Set master password: ", show='*')
    save_master_key(file_path, master_password)
    root.deiconify()

# Function to check the validity of the master key
def check_master_key(file_path):
    attempts = 0
    max_attempts = 5  # Set the max attempts here
    while attempts < max_attempts:
        root.withdraw()
        master_key = simpledialog.askstring("Password Manager", "Enter master key: ", show='*')
        root.deiconify()

        saved_master_key = load_master_key(file_path)

        if saved_master_key == generate_key(master_key):
            return True
        
        attempts += 1
        remaining_attempts = max_attempts - attempts
        print(f"Incorrect master key. {remaining_attempts} attempts remaining.")
    
    return False

# Function to add a new password entry
def add_password():
    dialog_window = tk.Toplevel(root)
    dialog_window.geometry("300x170")
    dialog_window.title("Add New Entry")

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Calculate the position to center the dialog window
    x_coordinate = int((screen_width - 300) / 2)
    y_coordinate = int((screen_height - 170) / 2)

    dialog_window.geometry(f"300x170+{x_coordinate}+{y_coordinate}")    

    def on_enter(event=None):
        nonlocal website_entry, username_entry, password_entry
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        if website and password:  # Allow empty username (treated as None)
            if not username:
                username = None

            master_key = load_master_key(config_file_path)
            encrypted_website = encrypt_data(website, master_key)
            encrypted_username = encrypt_data(username if username else "None", master_key)
            encrypted_password = encrypt_data(password, master_key)

            # Store the encrypted data in data.txt
            with open('data.txt', 'a') as file:
                file.write(f"Website: {encrypted_website.decode()}\n")
                file.write(f"Username: {encrypted_username.decode()}\n")
                file.write(f"Password: {encrypted_password.decode()}\n\n")

            # Create a frame for the new entry with a border
            entry_frame = tk.Frame(display, bd=2, relief=tk.RAISED)
            entry_frame.pack(pady=5, fill=tk.X)

            # Display the added website, username, and password inside the frame
            label_website = tk.Label(entry_frame, text=f"{website}")
            label_website.pack(anchor=tk.W)

            label_username = tk.Label(entry_frame, text=f"Username: {username if username else 'None'}")
            label_username.pack(anchor=tk.W)

            label_password = tk.Label(entry_frame, text=f"Password: {password}")
            label_password.pack(anchor=tk.W)

            # Update the display area to show the added entry
            display.window_create(tk.END, window=entry_frame)
            display.insert(tk.END, "\n")

            dialog_window.destroy()
            root.deiconify()

    website_label = tk.Label(dialog_window, text="Enter website:")
    website_label.pack()
    website_entry = tk.Entry(dialog_window)
    website_entry.pack()
    website_entry.focus_force()

    username_label = tk.Label(dialog_window, text="Enter username:")
    username_label.pack()
    username_entry = tk.Entry(dialog_window)
    username_entry.pack()

    password_label = tk.Label(dialog_window, text="Enter password:")
    password_label.pack()
    password_entry = tk.Entry(dialog_window, show='*')
    password_entry.pack()

    password_entry.bind("<Return>", on_enter)

    ok_button = tk.Button(dialog_window, text="     OK \t", command=on_enter)
    ok_button.pack(pady=10)

    dialog_window.grab_set()
    root.wait_window(dialog_window)

status_label = None

# Function to copy the password to the clipboard
def copy_password(event, password, label):
    pyperclip.copy(password)
    label.config(text="Password Copied!", fg="green")
    label.after(2000, lambda: label.config(text=f"Password: {password}", fg="black"))

# Function to handle the hover start event for password
def hover_start(event):
    event.widget.config(text="Copy password", fg="blue", cursor="hand2")

# Function to handle the hover end event for password
def hover_end(event, encrypted_password):
    master_key = load_master_key(config_file_path)
    decrypted_password = decrypt_data(encrypted_password, master_key)
    event.widget.config(text=f"Password: {decrypted_password}", fg="black", cursor="arrow")

# Function to copy the username to the clipboard
def copy_username(event, username, label):
    pyperclip.copy(username)
    label.config(text="Username Copied!", fg="green")
    label.after(2000, lambda: label.config(text=f"Username: {username}", fg="black"))

# Function to handle the hover start event for username
def hover_start_username(event):
    event.widget.config(text="Copy username", fg="red", cursor="hand2")

# Function to handle the hover end event for username
def hover_end_username(event, username):
    event.widget.config(text=f"Username: {username}", fg="black", cursor="arrow")

# Function to delete an entry
def delete_entry(entry_id):
    try:
        with open('data.txt', 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        print("No data file found.")
        return

    entry_to_delete = 4 * entry_id - 3  # Calculate the starting line to delete
    lines_to_delete = 4  # Number of lines to delete for each entry

    updated_lines = lines[:entry_to_delete - 1] + lines[entry_to_delete + lines_to_delete - 1:]  # Slice out the lines to delete

    with open('data.txt', 'w') as file:
        file.writelines(updated_lines)

# Function to delete entries related to a website
def delete_website(website):
    try:
        with open('data.txt', 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        print("No data file found.")
        return

    entry_to_delete = None
    for i, line in enumerate(lines):
        if website in line:
            entry_to_delete = i // 4  # Calculate the entry_id to delete
            break

    if entry_to_delete is not None:
        delete_entry(entry_to_delete + 1)  # Adding 1 to convert entry_id to 1-based indexing

# Function to open the edit window for managing entries
def open_edit_window():
    def delete_website(selected_website):
        try:
            with open('data.txt', 'r') as file:
                lines = file.readlines()
        except FileNotFoundError:
            print("No data file found.")
            return

        # Calculate the starting line for the selected website's entry
        entry_to_delete = 4 * selected_website + 1

        # Remove the corresponding lines from the data file
        updated_lines = lines[:entry_to_delete - 1] + lines[entry_to_delete + 3:]

        with open('data.txt', 'w') as file:
            file.writelines(updated_lines)
    
        # Refresh the displayed list after deletion
        refresh_website_list()

    def refresh_website_list():
        tree.delete(0, tk.END)  # Clear the current list

        try:
            with open('data.txt', 'r') as file:
                lines = file.readlines()
        except FileNotFoundError:
            print("No data file found.")
            return

        websites = {}
        for i, line in enumerate(lines):
            if i % 4 == 0:
                encrypted_website = line.strip().split(': ')[1]
                website = decrypt_data(encrypted_website.encode(), master_key)
                websites[i // 4 + 1] = website

        for idx, website in websites.items():
            tree.insert('end', f"{idx}. {website}")

    def backup_data():
        # Create a backup of the current data.txt file
        try:
            with open('data.txt', 'r') as file:
                original_data = file.read()
                with open('data_backup.txt', 'w') as backup_file:
                    backup_file.write(original_data)
        except FileNotFoundError:
            print("No data file found.")
            return

    def restore_backup():
        # Restore the backup to revert changes made in the edit window
        try:
            with open('data_backup.txt', 'r') as backup_file:
                backup_data = backup_file.read()
                with open('data.txt', 'w') as file:
                    file.write(backup_data)
        except FileNotFoundError:
            print("No backup file found.")
            return

    def save_changes():
        # Remove the backup file as changes are confirmed
        try:
            os.remove('data_backup.txt')
        except FileNotFoundError:
            pass

        # Clear the displayed entries
        for widget in display.winfo_children():
            widget.destroy()

        # Update and display the entries
        read_and_display_entries()

        edit_window.destroy()
        root.deiconify()

    def on_close():
        # Restore the backup and remove it upon closing the window by calling the restore_backup function
        restore_backup()
        try:
            os.remove('data_backup.txt')
        except FileNotFoundError:
            pass
        edit_window.destroy()
        root.deiconify()

    # Backup the data.txt upon entering the edit window
    backup_data()

    try:
        with open('data.txt', 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        print("No data file found.")
        return

    master_key = load_master_key(config_file_path)
    websites = {}
    for i, line in enumerate(lines):
        if i % 4 == 0:
            encrypted_website = line.strip().split(': ')[1]
            website = decrypt_data(encrypted_website.encode(), master_key)
            websites[i // 4] = website

    root.withdraw()

    edit_window = tk.Toplevel(root)
    edit_window.title("Edit Entries")
    edit_window.geometry("600x600")
    screen_width = edit_window.winfo_screenwidth()
    screen_height = edit_window.winfo_screenheight()

    x_coordinate = int((screen_width - 600) / 2)
    y_coordinate = int((screen_height - 600) / 2)

    edit_window.geometry(f"600x600+{x_coordinate}+{y_coordinate}")
    edit_window.configure(padx=20, pady=20)
    edit_window.protocol("WM_DELETE_WINDOW", on_close)

    label = tk.Label(edit_window, text="Websites")
    label.pack()

    tree = tk.Listbox(edit_window, font=("Arial", 12), height=20)
    tree.pack(fill='both', expand=True)
    tree.configure(highlightthickness=0, bd=0, selectbackground="#a6a6a6")

    for idx, website in websites.items():
        tree.insert('end', f"{idx+1}. {website}")

    def on_delete():
        selected_item = tree.curselection()
        if selected_item:
            selected_website = selected_item[0]
            delete_website(selected_website)

    delete_button = tk.Button(edit_window, text="Delete", command=on_delete)
    delete_button.pack()

    save_button = tk.Button(edit_window, text="Save Changes", command=save_changes)
    save_button.pack()

# Function to read and display all entries
def read_and_display_entries():
    global status_label

    try:
        with open('data.txt', 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        print("No data file found.")
        return

    entries = []
    temp_entry = {}
    for line in lines:
        if line.strip() == '':
            if temp_entry:
                entries.append(temp_entry)
                temp_entry = {}
        else:
            key, value = line.strip().split(': ', 1)
            temp_entry[key] = value

    master_key = load_master_key(config_file_path)

    for entry in entries:
        website = decrypt_data(entry['Website'].encode(), master_key)
        username = decrypt_data(entry['Username'].encode(), master_key)
        encrypted_password = entry['Password'].encode()
        password = decrypt_data(encrypted_password, master_key)

        entry_frame = tk.Frame(display, bd=2, relief=tk.RAISED)
        entry_frame.pack(pady=5, fill=tk.X)

        label_website = tk.Label(entry_frame, text=f"{website}")
        label_website.pack(anchor=tk.W)

        label_username = tk.Label(entry_frame, text=f"Username: {username}")
        label_username.pack(anchor=tk.W)

        label_password = tk.Label(entry_frame, text=f"Password: {password}", fg="black")
        label_password.pack(anchor=tk.W)

        label_password.bind("<Enter>", hover_start)
        label_password.bind("<Leave>", lambda event, encrypted_password=encrypted_password: hover_end(event, encrypted_password))
        label_password.bind("<Button-1>", lambda event, password=password, label=label_password: copy_password(event, password, label))

        label_username.bind("<Enter>", hover_start_username)
        label_username.bind("<Leave>", lambda event, encrypted_password=encrypted_password: hover_end_username(event,username)) 
        label_username.bind("<Button-1>", lambda event, username=username, label=label_username: copy_username(event, username, label))
        display.window_create(tk.END, window=entry_frame)
        display.insert(tk.END, "\n")

# Function to set up the password manager interface
def setup_password_manager(file_path):
    global display
    if not os.path.exists(file_path):
        set_master_key(file_path)
    access_granted = check_master_key(file_path)
    if not access_granted:
        print("Maximum attempts reached. Closing application.")
        root.destroy()
    else:
        window_width = 900
        window_height = 800
        root_width = root.winfo_screenwidth()
        root_height = root.winfo_screenheight()
        x_coordinate = int((root_width - window_width) / 2)
        y_coordinate = int((root_height - window_height) / 2)

        root.geometry(f"{window_width}x{window_height}+{x_coordinate}+{y_coordinate}")
        root.configure(bd=20, relief=tk.RIDGE, pady=30)

        display = tk.Text(root, height=37, width=80)
        display.pack()
        display.config(state=tk.DISABLED)

        status_label = tk.Label(root, text="", fg="green")
        status_label.pack()

        read_and_display_entries()

        bottom_frame = tk.Frame(root)
        bottom_frame.pack(side=tk.BOTTOM, pady=0)

        add_button = tk.Button(bottom_frame, text="+", width=87, height=2, command=add_password)
        add_button.pack()

        edit_button = tk.Button(bottom_frame, text="Edit Entries", width=87, height=2, command=open_edit_window)
        edit_button.pack()

        root.mainloop()

# File path for configuration
config_file_path = 'config.txt'
root = tk.Tk()
root.title("Password Manager")

# Initialize and set up the password manager interface
setup_password_manager(config_file_path)