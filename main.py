import tkinter as tk
from tkinter import messagebox
from hashing_utils import hash_password
from hashing_utils import verify_password
from AES_utils import encrypt_data
from AES_utils import decrypt_data
from RSA_utils import encrypt_data_with_rsa
from RSA_utils import decrypt_data_with_rsa
import base64
import socket
import os

# Server settings
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 57329

# File paths for storing user data
USER_CREDENTIALS = "user_data.txt"
PERSONAL_DETAILS_FILE = "personal_data.txt"
TRANSFER_LOG = "transfers.txt"

active_user = None  # Track the currently logged-in user
is_admin = False  # Track if the logged-in user is an admin

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))

def send_to_server(message):
    """Send a message to the server."""
    try:
        client_socket.sendall(message.encode())
    except Exception as e:
        print("Failed to send message to server:", e)

def is_base64_encoded(data: str) -> bool:
    try:
        # Attempt to decode from base64 and check if it can be re-encoded
        return base64.b64encode(base64.b64decode(data)).decode() == data
    except Exception as e:
        print(f"Failed base64 check: {e}")
        return False

def register_user():
    username = username_entry_register.get()
    password = password_entry_register.get()
    ssn = ssn_entry.get()
    address = address_entry.get()
    phone = phone_entry.get()
    country = country_entry.get()
    
    if username and password and ssn and address and phone and country:
        # Hash the password
        hashed_password = hash_password(password)
        
        # Encrypt personal details
        encrypted_ssn = encrypt_data(ssn)
        encrypted_address = encrypt_data(address)
        encrypted_phone = encrypt_data(phone)
        encrypted_country = encrypt_data(country)
        
        # Store user credentials
        with open(USER_CREDENTIALS, "a") as file:
            file.write(f"{username},{hashed_password}\n")
        
        # Store encrypted personal details
        with open(PERSONAL_DETAILS_FILE, "a") as file:
            file.write(f"{username},{encrypted_ssn},{encrypted_address},{encrypted_phone},{encrypted_country}\n")
        
        messagebox.showinfo("Success", "Registration successful!")
        send_to_server(f"User registered: {username}")
        register_screen.destroy()
    else:
        messagebox.showerror("Error", "All fields are required.")

def login_user():
    global active_user
    username = username_entry_login.get()
    password = password_entry_login.get()
    
    if username and password:
        # Open user_data.txt and check if the username and hashed password match
        with open(USER_CREDENTIALS, "r") as file:
            for record in file:
                stored_username, stored_hashed_password = record.strip().split(",")
                if username == stored_username:
                    # Verify the entered password with the stored hashed password
                    if verify_password(stored_hashed_password, password):
                        active_user = username  # Set active user
                        messagebox.showinfo("Success", "Login successful!")
                        send_to_server(f"User logged in: {username}")
                        login_screen.destroy()  # Close login window
                        open_post_login_options()
                        return
                    else:
                        messagebox.showerror("Error", "Incorrect username or password.")
                        return
        messagebox.showerror("Error", "Incorrect username or password.")
    else:
        messagebox.showerror("Error", "All fields are required.")

def show_personal_details():
    """Display the personal details of the active user."""
    if active_user:
        with open(PERSONAL_DETAILS_FILE, "r") as file:
            for record in file:
                username, encrypted_ssn, encrypted_address, encrypted_phone, encrypted_country = record.strip().split(",")
                if username == active_user:
                    # Decrypt personal details
                    ssn = decrypt_data(encrypted_ssn)
                    address = decrypt_data(encrypted_address)
                    phone = decrypt_data(encrypted_phone)
                    country = decrypt_data(encrypted_country)
                    
                    # Display details in a new window
                    details_window = tk.Tk()
                    details_window.title(f"{active_user}'s Personal Details")
                    
                    tk.Label(details_window, text="Social Security Number:").grid(row=0, column=0, sticky="e")
                    tk.Label(details_window, text=ssn).grid(row=0, column=1, sticky="w")

                    tk.Label(details_window, text="Address:").grid(row=1, column=0, sticky="e")
                    tk.Label(details_window, text=address).grid(row=1, column=1, sticky="w")

                    tk.Label(details_window, text="Phone:").grid(row=2, column=0, sticky="e")
                    tk.Label(details_window, text=phone).grid(row=2, column=1, sticky="w")

                    tk.Label(details_window, text="Country:").grid(row=3, column=0, sticky="e")
                    tk.Label(details_window, text=country).grid(row=3, column=1, sticky="w")
                    return

def open_post_login_options():
    """Open the post-login options interface."""
    post_login_window = tk.Tk()
    post_login_window.title(f"Welcome, {active_user}")

    # Button to open the transfer interface
    btn_transfer_interface = tk.Button(post_login_window, text="Open Transfer Interface", command=open_transfer_interface)
    btn_transfer_interface.pack(pady=10)

    # Button to show personal details
    btn_show_details = tk.Button(post_login_window, text="Show Personal Details", command=show_personal_details)
    btn_show_details.pack(pady=10)


def process_transfer():
    account_id = account_entry.get()
    transfer_amount = amount_entry.get()
    
    if account_id and transfer_amount and active_user:
        try:
            # Load the RSA public key
            with open("public_key.pem", "rb") as pub_file:
                public_key = pub_file.read()
            
            # Encrypt transfer data
            transfer_data = f"{active_user},{account_id},{transfer_amount}"
            encrypted_transfer = encrypt_data_with_rsa(transfer_data, public_key)
            
            # Debug: Print the encrypted transfer data before saving
            print("Encrypted transfer (base64):", encrypted_transfer)
            
            # Log the encrypted transfer to transfers.txt
            with open(TRANSFER_LOG, "a") as file:
                file.write(f"{encrypted_transfer}\n")
            
            messagebox.showinfo("Success", "Transfer recorded successfully.")
            send_to_server(f"Transfer submitted by {active_user}")
        except Exception as e:
            messagebox.showerror("Error", f"Transfer failed: {e}")
    else:
        messagebox.showerror("Error", "All fields are required.")

def view_transfers():
    if os.path.exists(TRANSFER_LOG):
        try:
            # Load the RSA private key
            with open("private_key.pem", "rb") as priv_file:
                private_key = priv_file.read()

            # Read and decrypt each transfer record
            with open(TRANSFER_LOG, "r") as file:
                transfers = file.readlines()
                history_text = "Transfer Log:\n"
                
                for entry in transfers:
                    entry = entry.strip()  # Clean up any whitespace
                    print(f"Processing entry: {entry}")

                    # Check if entry is base64-encoded (encrypted) or plaintext
                    if is_base64_encoded(entry):
                        print("Entry is detected as base64-encoded, attempting to decrypt...")
                        # If encrypted, decrypt it
                        try:
                            decrypted_entry = decrypt_data_with_rsa(entry, private_key)
                            sender, account, amount = decrypted_entry.split(',')
                            history_text += f"{sender} sent {amount} to account {account}\n"
                        except Exception as e:
                            print(f"Decryption failed for entry: {entry}, error: {e}")
                            continue  # Skip this entry if decryption fails
                    else:
                        print("Entry detected as plaintext, processing without decryption...")
                        # If plaintext, handle it directly
                        try:
                            sender, account, amount = entry.split(',')
                            history_text += f"{sender} sent {amount} to account {account}\n"
                        except ValueError as ve:
                            print(f"Invalid format for plaintext entry: {entry}, error: {ve}")
                            continue  # Skip this entry if it has an invalid format
                
                transfer_label.config(text=history_text)
        except Exception as e:
            print(f"Failed to load transfer logs: {e}")
            transfer_label.config(text=f"Failed to load transfer logs: {e}")
    else:
        transfer_label.config(text="No transfer records found.")

def open_transfer_interface():
    # Sender interface
    global sender_screen, account_entry, amount_entry
    sender_screen = tk.Tk()
    sender_screen.title(f"Kasrawy Transfer - Sender ({active_user})")
    
    tk.Label(sender_screen, text="Account Number:").grid(row=0, column=0)
    account_entry = tk.Entry(sender_screen)
    account_entry.grid(row=0, column=1)

    tk.Label(sender_screen, text="Amount:").grid(row=1, column=0)
    amount_entry = tk.Entry(sender_screen)
    amount_entry.grid(row=1, column=1)

    submit_button = tk.Button(sender_screen, text="Submit Transfer", command=process_transfer)
    submit_button.grid(row=2, columnspan=2)

    # Receiver interface - show full log only if the user is an admin
    global receiver_screen, transfer_label
    receiver_screen = tk.Tk()
    receiver_screen.title("Kasrawy Transfer - Receiver")

    transfer_label = tk.Label(receiver_screen, text="Transfer Log:")
    transfer_label.pack()

    view_button = tk.Button(receiver_screen, text="View Transfers", command=show_transfers if is_admin else show_user_transfers)
    view_button.pack()

def show_transfers():
    """Display full transaction log for admin."""
    if os.path.exists(TRANSFER_LOG):
        with open(TRANSFER_LOG, "r") as file:
            transfers = file.readlines()
            display_text = "Complete Transfer History:\n"
            for line in transfers:
                display_text += line
            transfer_label.config(text=display_text)
    else:
        transfer_label.config(text="No transfer data available.")

def show_user_transfers():
    """Display only the user's transfers."""
    if os.path.exists(TRANSFER_LOG):
        try:
            # Load the RSA private key
            with open("private_key.pem", "rb") as priv_file:
                private_key = priv_file.read()

            # Read and decrypt each transfer record
            with open(TRANSFER_LOG, "r") as file:
                transfers = file.readlines()
                display_text = f"Transfer History for {active_user}:\n"
                
                for encrypted_entry in transfers:
                    encrypted_entry = encrypted_entry.strip()
                    decrypted_entry = decrypt_data_with_rsa(encrypted_entry, private_key)
                    
                    # Split the decrypted entry into sender, account, and amount
                    sender, account, amount = decrypted_entry.split(',')
                    
                    # Display only the current user's transfers
                    if sender == active_user:
                        display_text += f"{sender} sent {amount} to account {account}\n"
                
                transfer_label.config(text=display_text)
        except Exception as e:
            transfer_label.config(text=f"Failed to load transfer logs: {e}")
    else:
        transfer_label.config(text="No transfer records found.")
    
def open_register_screen():
    global register_screen, username_entry_register, password_entry_register
    global ssn_entry, address_entry, phone_entry, country_entry

    register_screen = tk.Tk()
    register_screen.title("Register")
    
    # Credentials Section
    credentials_label = tk.Label(register_screen, text="Credentials", font=('Arial', 14, 'bold'))
    credentials_label.grid(row=0, column=0, columnspan=2, pady=(10, 0))
    
    tk.Label(register_screen, text="Username:").grid(row=1, column=0, sticky="e")
    username_entry_register = tk.Entry(register_screen)
    username_entry_register.grid(row=1, column=1)
    
    tk.Label(register_screen, text="Password:").grid(row=2, column=0, sticky="e")
    password_entry_register = tk.Entry(register_screen, show="*")
    password_entry_register.grid(row=2, column=1)
    
    # Personal Details Section
    personal_details_label = tk.Label(register_screen, text="Personal Details", font=('Arial', 14, 'bold'))
    personal_details_label.grid(row=3, column=0, columnspan=2, pady=(10, 0))
    
    tk.Label(register_screen, text="SSN:").grid(row=4, column=0, sticky="e")
    ssn_entry = tk.Entry(register_screen)
    ssn_entry.grid(row=4, column=1)
    
    tk.Label(register_screen, text="Address:").grid(row=5, column=0, sticky="e")
    address_entry = tk.Entry(register_screen)
    address_entry.grid(row=5, column=1)
    
    tk.Label(register_screen, text="Phone:").grid(row=6, column=0, sticky="e")
    phone_entry = tk.Entry(register_screen)
    phone_entry.grid(row=6, column=1)
    
    tk.Label(register_screen, text="Country:").grid(row=7, column=0, sticky="e")
    country_entry = tk.Entry(register_screen)
    country_entry.grid(row=7, column=1)
    
    # Register Button
    register_button = tk.Button(register_screen, text="Register", command=register_user)
    register_button.grid(row=8, columnspan=2, pady=(10, 10))

def open_login_screen():
    global login_screen, username_entry_login, password_entry_login
    login_screen = tk.Tk()
    login_screen.title("Login")
    
    tk.Label(login_screen, text="Username:").grid(row=0, column=0)
    username_entry_login = tk.Entry(login_screen)
    username_entry_login.grid(row=0, column=1)
    
    tk.Label(login_screen, text="Password:").grid(row=1, column=0)
    password_entry_login = tk.Entry(login_screen, show="*")
    password_entry_login.grid(row=1, column=1)
    
    login_button = tk.Button(login_screen, text="Login", command=login_user)
    login_button.grid(row=2, columnspan=2)

# Main interface for user options
main_screen = tk.Tk()
main_screen.title("Kasrawy Transfer Application")

register_btn = tk.Button(main_screen, text="Register", command=open_register_screen)
register_btn.pack()

login_btn = tk.Button(main_screen, text="Login", command=open_login_screen)
login_btn.pack()

main_screen.mainloop()
