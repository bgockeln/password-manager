# Ben's Password Manager

I wanted to gain experience with encryption, so I created a very simple password manager that uses Python's `cryptography` library. `Fernet` is used to encrypt and decrypt passwords, and `hazmat` is used to derive a strong master password key.

When first running the program, the user must enter a master password. If none exists, one will be created at this point. Hazmat turns the master password into a secure key, stored in `master.key`, which `Fernet` then uses for encrypting and decrypting the password file.

After a successful login, the user can: add, list, delete, and search passwords. Passwords are encrypted/decrypted with `Fernet` and stored in `passwords.dat`.

> ⚠️ If you forget your master password, there is no way to recover it.  
> Deleting `master.key` will reset the application, allowing you to create a new master password and start with an empty password list.

## Note on the Textual GUI Version

I originally thought Textual would be perfect for creating a simple GUI for this script. In theory, it is. However, it complicated things far more than expected, so I may not revisit it. Since a lot of work went into it, I’m including it here, but the main project is the CLI version.
