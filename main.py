import tkinter as tk
from tkinter import messagebox
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

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))

def send_to_server(message):
    """Send a message to the server."""
    try:
        client_socket.sendall(message.encode())
    except Exception as e:
        print("Failed to send message to server:", e)

def register_user():
    username = username_entry_register.get()
    password = password_entry_register.get()
    ssn = ssn_entry.get()
    address = address_entry.get()
    phone = phone_entry.get()
    country = country_entry.get()
    
    if username and password and ssn and address and phone and country:
        # Store user credentials
        with open(USER_CREDENTIALS, "a") as file:
            file.write(f"{username},{password}\n")
        
        # Store personal details
        with open(PERSONAL_DETAILS_FILE, "a") as file:
            file.write(f"{username},{ssn},{address},{phone},{country}\n")
        
        messagebox.showinfo("Success", "Registration successful!")
        send_to_server(f"User registered: {username}")
        register_screen.destroy()  # Close the registration window
    else:
        messagebox.showerror("Error", "All fields are required.")

def login_user():
    global active_user
    username = username_entry_login.get()
    password = password_entry_login.get()
    
    if username and password:
        # Validate credentials
        with open(USER_CREDENTIALS, "r") as file:
            for record in file:
                user, pwd = record.strip().split(",")
                if username == user and password == pwd:
                    active_user = username  # Set active user
                    messagebox.showinfo("Success", "Login successful!")
                    send_to_server(f"User logged in: {username}")
                    login_screen.destroy()  # Close login window
                    open_post_login_options()
                    return
        messagebox.showerror("Error", "Incorrect username or password.")
    else:
        messagebox.showerror("Error", "All fields are required.")

def show_personal_details():
    """Display the personal details of the active user."""
    if active_user:
        with open(PERSONAL_DETAILS_FILE, "r") as file:
            for record in file:
                username, ssn, address, phone, country = record.strip().split(",")
                if username == active_user:
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
            # Log transfer data
            with open(TRANSFER_LOG, "a") as file:
                file.write(f"{active_user},{account_id},{transfer_amount}\n")
            messagebox.showinfo("Success", "Transfer recorded successfully.")
            send_to_server(f"Transfer submitted by {active_user}: {transfer_amount} to account {account_id}")
        except Exception as e:
            messagebox.showerror("Error", f"Transfer failed: {e}")
    else:
        messagebox.showerror("Error", "All fields are required.")

def view_transfers():
    if os.path.exists(TRANSFER_LOG):
        # Display transfer history
        with open(TRANSFER_LOG, "r") as file:
            transfer_data = file.readlines()
            history_text = "Transfer Log:\n"
            for entry in transfer_data:
                user, account, amount = entry.strip().split(",")
                history_text += f"{user} sent {amount} to account {account}\n"
            transfer_label.config(text=history_text)
    else:
        transfer_label.config(text="No transfer records found.")

def open_transfer_interface():
    # Sender interface
    global sender_screen, account_entry, amount_entry
    sender_screen = tk.Tk()
    sender_screen.title(f"Money Transfer - Sender ({active_user})")
    
    tk.Label(sender_screen, text="Account Number:").grid(row=0, column=0)
    account_entry = tk.Entry(sender_screen)
    account_entry.grid(row=0, column=1)

    tk.Label(sender_screen, text="Amount:").grid(row=1, column=0)
    amount_entry = tk.Entry(sender_screen)
    amount_entry.grid(row=1, column=1)

    submit_button = tk.Button(sender_screen, text="Submit Transfer", command=process_transfer)
    submit_button.grid(row=2, columnspan=2)

    # Receiver interface
    global receiver_screen, transfer_label
    receiver_screen = tk.Tk()
    receiver_screen.title("Money Transfer - Receiver")
    
    transfer_label = tk.Label(receiver_screen, text="Transfer Log:")
    transfer_label.pack()

    view_button = tk.Button(receiver_screen, text="View Transfers", command=view_transfers)
    view_button.pack()
    
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
main_screen.title("Money Transfer Application")

register_btn = tk.Button(main_screen, text="Register", command=open_register_screen)
register_btn.pack()

login_btn = tk.Button(main_screen, text="Login", command=open_login_screen)
login_btn.pack()

main_screen.mainloop()
