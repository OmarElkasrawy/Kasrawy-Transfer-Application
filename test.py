import tkinter as tk
from tkinter import messagebox
import os

# File paths for storing user data
USER_CREDENTIALS = "user_data.txt"
TRANSFER_LOG = "transfers.txt"

active_user = None  # Track the currently logged-in user

def register_user():
    username = username_entry_register.get()
    password = password_entry_register.get()
    
    if username and password:
        # Store user credentials
        with open(USER_CREDENTIALS, "a") as file:
            file.write(f"{username},{password}\n")
        messagebox.showinfo("Success", "Registration successful!")
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
                    login_screen.destroy()  # Close login window
                    open_transfer_interface()
                    return
        messagebox.showerror("Error", "Incorrect username or password.")
    else:
        messagebox.showerror("Error", "All fields are required.")

def process_transfer():
    account_id = account_entry.get()
    transfer_amount = amount_entry.get()
    
    if account_id and transfer_amount and active_user:
        try:
            # Log transfer data
            with open(TRANSFER_LOG, "a") as file:
                file.write(f"{active_user},{account_id},{transfer_amount}\n")
            messagebox.showinfo("Success", "Transfer recorded successfully.")
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
    register_screen = tk.Tk()
    register_screen.title("Register")
    
    tk.Label(register_screen, text="Username:").grid(row=0, column=0)
    username_entry_register = tk.Entry(register_screen)
    username_entry_register.grid(row=0, column=1)
    
    tk.Label(register_screen, text="Password:").grid(row=1, column=0)
    password_entry_register = tk.Entry(register_screen, show="*")
    password_entry_register.grid(row=1, column=1)
    
    register_button = tk.Button(register_screen, text="Register", command=register_user)
    register_button.grid(row=2, columnspan=2)

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
