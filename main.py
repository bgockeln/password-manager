# base64: used to encode keys in a format that Fernet accepts.
# json: used to serialize/deserialize password lists (not files directly).
# getpass: safely hides master password input.
# cryptography.hazmat and Fernet: handle key derivation and encryption/decryption.
import os
import base64
import json
import getpass
from typing import List, Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# filenames for storing the master password key and encrypted passwords.
MASTER_FILE= "master.key"
PASSWORD_FILE = "passwords.dat"

#------------------------
# Storage/Crypto Function
#------------------------

def save_master_password(master_password: str):
    """
    Derive a key from the master password and store it securely with salt
    """
    salt = os.urandom(16) # generate a random 16-byte salt.
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32, # key length in bytes.
        salt = salt,
        iterations = 100_000, # number of PBKDF2 iterations (security parameter) WHAT IS THAT.
        backend = default_backend()
    )
    key = kdf.derive(master_password.encode()) # derive key from password.

    # Store salt and key together. 
    # Save salt first, then the key.
    with open(MASTER_FILE, "wb") as f:
        f.write(salt + key )

def verify_master_password(master_password: str) -> bool:
    """
    Check if the entered master password matches the stored key.
    """
    if not os.path.exists(MASTER_FILE):
        return False # if no master password set yet.

    with open(MASTER_FILE, "rb") as f:
        data = f.read()

    salt = data[:16] # first 16 bytes are the salt.
    stored_key = data[16:] # remaing bytes are the derived key.

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100_000,
        backend = default_backend()
    )
    try:
        # raises an exception if password is wrong.
        kdf.verify(master_password.encode(), stored_key)
        return True
    except:
        return False

def derive_key(master_password: str) -> bytes:
    """
    Derive a Fernet key from the master password.
    This key will be used to encrypt/decrypt the password list.
    """
    salt = b"static_salt_for_demo" # # static salt for Fernet key (demo only).
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt, 
        iterations = 100_000,
        backend = default_backend()
    )
    # Fernet requires a base64-encoded key.
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def load_passwords(master_key: bytes) -> List[Tuple[str, str]]:
    """
    Decrypt and load the stored passwords.
    Returns a list of (account_name, password) tuples.
    """
    if not os.path.exists(PASSWORD_FILE):
        return []

    with open(PASSWORD_FILE, "rb") as f:
        encrypted = f.read()

    fernet = Fernet(master_key)
    try:
        decrypted = fernet.decrypt(encrypted).decode() # decrypt bytes -> string.
        return json.loads(decrypted) # parse JSON string -> Python list.
    except:
        return [] # if decryption fails, return empty list.

def save_passwords(master_key: bytes, passwords: List[Tuple[str, str]]):
    fernet = Fernet(master_key)
    data = json.dumps(passwords).encode() # serialize list -> JSON bytes.
    encrypted = fernet.encrypt(data)
    with open(PASSWORD_FILE, "wb") as f:
        f.write(encrypted)

def clear_screen():
    """
    Clear the terminal screen, works on Windows and Unix.
    """
    os.system("cls" if os.name=="nt" else "clear")

#------------------------
# Main Application Loop
#------------------------

def main():
    master_key = None
    passwords = []

    # If no master password exists, ask to set one.
    if not os.path.exists(MASTER_FILE):
        pw = input("Set a master password: ")
        save_master_password(pw)
        master_key = derive_key(pw)
        print("Master password set!")
    else:
        # Loop until correct master password is entered.
        while True:
            pw = getpass.getpass("Enter master password: ")
            if verify_master_password(pw):
                master_key = derive_key(pw)
                passwords = load_passwords(master_key)
                print("Login successful!\n")
                break
            else:
                print("Incorrect password, try again.")

    # Mein menu loop.
    while True:
        print("\n --- Ben's Password Manager ---")
        print("1. Add Password")
        print("2. Delete Password")
        print("3. List Passwords")
        print("4. Search Passwords")
        print("5. Quit")
        choice = input("Chose an option: ")

        if choice == "1":
            # Add a new password.
            name = input("Account Name: ").strip()
            pw = input("Password: ").strip()
            if not name or not pw:
                print("Account and password cannot be empty!")
                continue
            if len(name) > 30 or len(pw) > 30:
                print("Account and password cannot be longer than 30 characters!")
                continue
            passwords.append((name, pw))
            save_passwords(master_key, passwords)
            print(f"Added passwords for {name}.")
            input("Press any key: ")
            clear_screen()

        elif choice == "2":
            # Delete a password by account name.
            name = input("Account to delete: ")
            passwords = [(n, p) for n, p in passwords if n != name]
            save_passwords(master_key, passwords)
            print(f"Deleted password for {name}.")
            input("Press any key: ")
            clear_screen()
        
        elif choice == "3":
            # List all stored passwords.
            if not passwords:
                print("No passwords stored.")
                input("Press any key: ")
                clear_screen()
            else:
                print("Account Name : Password") 
                for n, p in passwords:
                    print(f"{n}: {p}")
                input("Press any key: ")
                clear_screen()
        
        elif choice == "4":
            # Search passwords by account name.
            term = input("Search term: "). lower()
            results = [(n, p) for n, p in passwords if term in n.lower()]
            if not results:
                print("No matches found.")
            else:
                for n, p in results:
                    print(f"{n}: {p}")
                    input("Press any key: ")
                    clear_screen()

        elif choice == "5":
            # Exit program.
            print("Exiting...")
            break

        else:
            print("Invalid choice")
            input("Press any key: ")
            clear_screen()

if __name__ == "__main__":
    main()