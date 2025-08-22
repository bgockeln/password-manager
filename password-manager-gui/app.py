import os
import base64
import json
from textual.message import Message
from typing import List, Tuple
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Static, Input, ListView, ListItem, Label
from textual.containers import Horizontal, Vertical
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

#------------------------
# Modals
#------------------------

class SetMasterModal(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Set Master Password", id = "set_prompt")
        self.input_pw = Input(password = True, placeholder = "New Master Password", id = "set_input")
        yield self.input_pw
        self.btn_submit = Button("Set Password", id = "set_submit")
        yield self.btn_submit

class LoginModal(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Enter Master Password", id = "login_prompt")
        self.input_pw = Input(password = True, placeholder = "Master Password", id = "login_input")
        yield self.input_pw
        self.btn_submit = Button("Submit", id = "login_submit")
        yield self.btn_submit

    async def on_input_submitted(self, event: Input.Submitted):
        # Enter support for submitting password
        self.post_message(Button.Pressed(self.btn_submit))

#------------------------
# Main App
#------------------------

class PasswordManagerApp(App):
    CSS_PATH = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.master_key = None
        self.passwords = [] 
        self.login_modal = None
        self.set_modal = None
        self.current_modal = None

    async def on_mount(self):
        if not os.path.exists(MASTER_FILE):
            self.set_modal = SetMasterModal()
            await self.mount(self.set_modal)
        else:
            self.login_modal = LoginModal()
            await self.mount(self.login_modal)
    
    async def on_button_pressed(self, event):
        button_id = event.button.id

        if button_id == "add":
            await self.open_modal(AddPasswordModal)
        elif button_id == "delete":
            # Get selected item
            selected = self.password_list.index
            if selected is not None and selected < len(self.passwords):
                del self.passwords[selected]
                save_passwords(self.master_key, self.passwords)
                await self.update_password_list()
        elif button_id == "search":
            await self.open_modal(SearchPasswordModal)
        elif button_id == "quit":
            self.exit()

        # Modal submit buttons
        elif button_id == "add_submit" and self.current_modal:
            name = self.current_modal.input_name.value
            pw = self.current_modal.input_pw.value
            self.passwords.append((name, pw))
            save_passwords(self.master_key, self.passwords)
            await self.current_modal.remove()
            self.current_modal = None
            await self.update_password_list()

        elif button_id == "delete_submit" and self.current_modal:
            name = self.current_modal.input_name.value
            self.passwords = [(n, p) for n, p in self.passwords if n != name]
            save_passwords(self.master_key, self.passwords)
            await self.current_modal.remove()
            self.current_modal = None
            await self.update_password_list()

        elif button_id == "search_submit" and self.current_modal:
            name = self.current_modal.input_name.value
            results = [(n, p) for n, p in self.passwords if name.lower() in n.lower()]

            # Clear current list
            await self.password_list.clear()

            if results:
                for n, p in results:
                    await self.password_list.mount(ListItem(Label(f"{n}: {p}")))
            else:
                await self.password_list.mount(ListItem(Label("No results found")))

            await self.current_modal.remove()
            self.current_modal = None

        # First time setup
        if button_id == "set_submit":
            pw = self.set_modal.input_pw.value
            save_master_password(pw)
            await self.set_modal.remove()
            self.login_modal = LoginModal()
            await self.mount(self.login_modal)
            return

        # Existing login
        if button_id == "login_submit":
            pw = self.login_modal.input_pw.value
            if verify_master_password(pw):
                self.master_key = derive_key(pw) # for encryption
                self.passwords = load_passwords(self.master_key) # load saved passwords
                await self.login_modal.remove() #hide login
                await self.show_main_ui() # mount main gui
                await self.update_password_list() # show loaded passwords
            else: self.login_modal.query_one("#login_prompt", Static).update("Incorrect Password")
        
        # Main Menu

    async def open_modal(self, modal_class):
        #remove existing modal if there is one already
        if self.current_modal:
            await self.current_modal.remove()
            self.current_modal = None
        
        # mount it
        self.current_modal = modal_class()
        await self.mount(self.current_modal)

    async def show_main_ui(self):
        # Header and Footer
        self.header = Header(show_clock = True)
        self.footer = Footer()
        await self.mount(self.header)
        await self.mount(self.footer)

        # Main Container
        self.main = Horizontal(id = "main")
        await self.mount(self.main)

        # Left: Menu
        self.menu = Vertical(id = "menu")
        await self.main.mount(self.menu)
        await self.menu.mount(Button("Add Password", id = "add"))
        await self.menu.mount(Button("Delete Password", id = "delete"))
        await self.menu.mount(Button("Search Password", id = "search"))
        await self.menu.mount(Button("Quit", id = "quit"))

        # Right: Content
        self.content = Vertical(id = "content")
        await self.main.mount(self.content)

        # Use ListView for clickable entries
        from textual.widgets import ListView, ListItem, Label

        self.password_list = ListView(id="password_list")
        await self.content.mount(self.password_list)

    async def update_password_list(self):
        # Clear existing items
        await self.password_list.clear()

        if not self.passwords:
            await self.password_list.mount(ListItem(Label("No Passwords yet.")))
            return

        for name, pw in self.passwords:
            # Each entry is clickable/selectable
            item = ListItem(Label(f"{name}: {pw}"))
            await self.password_list.mount(item)

class AddPasswordModal(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Add New Password")
        self.input_name = Input(placeholder = "Account/Service")
        yield self.input_name
        self.input_pw = Input(placeholder = "Password")
        yield self.input_pw
        self.btn_submit = Button("Save", id = "add_submit")
        yield self.btn_submit

    async def on_input_submitted(self, event: Input.Submitted):
        # Enter support for submitting password
        self.post_message(Button.Pressed(self.btn_submit))

class DeletePasswordModal(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Delete Password by Account Name")
        self.input_name = Input(placeholder = "Account/Service")
        yield self.input_name
        self.btn_submit = Button("Delete", id = "delete_submit")
        yield self.btn_submit

    async def on_input_submitted(self, event: Input.Submitted):
        # Enter support for submitting password
        self.post_message(Button.Pressed(self.btn_submit))

class SearchPasswordModal(Vertical):
    def compose(self) -> ComposeResult:
        yield Static("Search Passwords")
        self.input_name = Input(placeholder = "Search Term")
        yield self.input_name
        self.btn_submit = Button("Search", id = "search_submit")
        yield self.btn_submit

    async def on_input_submitted(self, event: Input.Submitted):
        # Enter support for submitting password
        self.post_message(Button.Pressed(self.btn_submit))

# Run
 
if __name__ == "__main__":
    app = PasswordManagerApp()
    app.run()