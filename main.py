import os
import base64
import json
import getpass
from typing import List, Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

MASTER_FILE= "master.key"
PASSWORD_FILE = "passwords.dat"

#------------------------
# Storage/Crypto Function
#------------------------

def save_master_password(master_password: str):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100_000,
        backend = default_backend()
    )
    key = kdf.derive(master_password.encode())
    # Store salt + key together
    with open(MASTER_FILE, "wb") as f:
        f.write(salt + key )

def verify_master_password(master_password: str) -> bool:
    if not os.path.exists(MASTER_FILE):
        return False
    with open(MASTER_FILE, "rb") as f:
        data = f.read()
    salt = data[:16]
    stored_key = data[16:]
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100_000,
        backend = default_backend()
    )
    try:
        kdf.verify(master_password.encode(), stored_key)
        return True
    except:
        return False

def derive_key(master_password: str) -> bytes:
    # Return a Fernet key derived from master password
    salt = b"static_salt_for_demo" #temp later you can store per user
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt, 
        iterations = 100_000,
        backend = default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def load_passwords(master_key: bytes) -> List[Tuple[str, str]]:
    if not os.path.exists(PASSWORD_FILE):
        return []
    with open(PASSWORD_FILE, "rb") as f:
        encrypted = f.read()
    fernet = Fernet(master_key)
    try:
        decrypted = fernet.decrypt(encrypted).decode()
        return json.loads(decrypted) # list of name [name, pw]
    except:
        return []

def save_passwords(master_key: bytes, passwords: List[Tuple[str, str]]):
    fernet = Fernet(master_key)
    data = json.dumps(passwords).encode()
    encrypted = fernet.encrypt(data)
    with open(PASSWORD_FILE, "wb") as f:
        f.write(encrypted)

def main():
    master_key = None
    passwords = []

    if not os.path.exists(MASTER_FILE):
        pw = input("Set a master password: ")
        save_master_password(pw)
        master_key = derive_key(pw)
        print("Master password set!")
    else:
        while True:
            pw = getpass.getpass("Enter master password: ")
            #pw = input("Enter master password: ")
            if verify_master_password(pw):
                master_key = derive_key(pw)
                passwords = load_passwords(master_key)
                print("Login successful!\n")
                break
            else:
                print("Incorrect password, try again.")
    
    while True:
        print("\n --- Ben's Password Manager ---")
        print("1. Add Password")
        print("2. Delete Password")
        print("3. List Passwords")
        print("4. Search Passwords")
        print("5. Quit")
        choice = input("Chose an option: ")

        if choice == "1":
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
            (os.system("cls" if os.name=="nt" else "clear"))

        elif choice == "2":
            name = input("Account to delete: ")
            passwords = [(n, p) for n, p in passwords if n != name]
            save_passwords(master_key, passwords)
            print(f"Deleted password for {name}.")
            input("Press any key: ")
            (os.system("cls" if os.name=="nt" else "clear"))
        
        elif choice == "3":
            if not passwords:
                print("No passwords stored.")
                input("Press any key: ")
                (os.system("cls" if os.name=="nt" else "clear"))
            else:
                print("Account Name : Password") 
                for n, p in passwords:
                    print(f"{n}: {p}")
                input("Press any key: ")
                (os.system("cls" if os.name=="nt" else "clear"))
        
        elif choice == "4":
            term = input("Search term: "). lower()
            results = [(n, p) for n, p in passwords if term in n.lower()]
            if not results:
                print("No matches found.")
            else:
                for n, p in results:
                    print(f"{n}: {p}")
                    input("Press any key: ")
                    (os.system("cls" if os.name=="nt" else "clear"))

        elif choice == "5":
            print("Exiting...")
            break

        else:
            print("Invalid choice")
            input("Press any key: ")
            (os.system("cls" if os.name=="nt" else "clear"))

if __name__ == "__main__":
    main()