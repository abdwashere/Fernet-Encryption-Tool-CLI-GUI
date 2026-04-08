import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from cryptography.fernet import Fernet, InvalidToken
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# =========================
# CRYPTO HELPERS
# =========================

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_with_key(message: str, key: bytes) -> bytes:
    cipher = Fernet(key)
    return cipher.encrypt(message.encode("utf-8"))


def decrypt_with_key(token: str, key: bytes) -> str:
    cipher = Fernet(key)
    decrypted = cipher.decrypt(token.encode("utf-8"))
    return decrypted.decode("utf-8")


def encrypt_with_password(message: str, password: str) -> tuple[bytes, bytes]:
    """
    Returns (salt, encrypted_token)
    """
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    token = encrypt_with_key(message, key)
    return salt, token


def decrypt_with_password(token: str, password: str, salt_b64: str) -> str:
    salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
    key = derive_key_from_password(password, salt)
    return decrypt_with_key(token, key)


# =========================
# MAIN APP
# =========================

class SecureFernetApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Encryption Tool")
        self.root.geometry("980x720")
        self.root.minsize(950, 680)

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.status_var = tk.StringVar()
        self.status_var.set("Ready.")

        self.create_ui()

    # -------------------------
    # UI SETUP
    # -------------------------
    def create_ui(self):
        title = tk.Label(
            self.root,
            text="🔐 Secure Encryption Tool (Fernet)",
            font=("Arial", 20, "bold")
        )
        title.pack(pady=12)

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=12, pady=8)

        self.encrypt_tab = ttk.Frame(notebook)
        self.decrypt_tab = ttk.Frame(notebook)

        notebook.add(self.encrypt_tab, text="Encrypt")
        notebook.add(self.decrypt_tab, text="Decrypt")

        self.build_encrypt_tab()
        self.build_decrypt_tab()

        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            anchor="w",
            relief="sunken",
            bd=1,
            font=("Arial", 10)
        )
        status_bar.pack(fill="x", side="bottom")

    # -------------------------
    # ENCRYPT TAB
    # -------------------------
    def build_encrypt_tab(self):
        top_frame = ttk.Frame(self.encrypt_tab)
        top_frame.pack(fill="x", padx=10, pady=10)

        # Encryption mode
        mode_frame = ttk.LabelFrame(top_frame, text="Encryption Mode")
        mode_frame.pack(fill="x", pady=5)

        self.encrypt_mode = tk.StringVar(value="key")

        ttk.Radiobutton(
            mode_frame, text="Fernet Key Mode", variable=self.encrypt_mode, value="key",
            command=self.toggle_encrypt_mode
        ).grid(row=0, column=0, padx=10, pady=10, sticky="w")

        ttk.Radiobutton(
            mode_frame, text="Password Mode", variable=self.encrypt_mode, value="password",
            command=self.toggle_encrypt_mode
        ).grid(row=0, column=1, padx=10, pady=10, sticky="w")

        # Message input
        input_frame = ttk.LabelFrame(self.encrypt_tab, text="Message to Encrypt")
        input_frame.pack(fill="both", expand=False, padx=10, pady=8)

        self.encrypt_input = scrolledtext.ScrolledText(
            input_frame, height=10, wrap=tk.WORD, font=("Consolas", 11)
        )
        self.encrypt_input.pack(fill="both", expand=True, padx=8, pady=8)

        # Key/Password settings
        settings_frame = ttk.LabelFrame(self.encrypt_tab, text="Key / Password Settings")
        settings_frame.pack(fill="x", padx=10, pady=8)

        # KEY MODE widgets
        self.use_existing_key_var = tk.BooleanVar(value=False)

        self.use_existing_key_check = ttk.Checkbutton(
            settings_frame,
            text="Use existing Fernet key instead of generating a new one",
            variable=self.use_existing_key_var,
            command=self.toggle_existing_key
        )
        self.use_existing_key_check.grid(row=0, column=0, columnspan=3, padx=10, pady=6, sticky="w")

        ttk.Label(settings_frame, text="Fernet Key:").grid(row=1, column=0, padx=10, pady=6, sticky="w")
        self.encrypt_key_entry = ttk.Entry(settings_frame, width=70, show="•")
        self.encrypt_key_entry.grid(row=1, column=1, padx=5, pady=6, sticky="w")

        self.encrypt_show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            settings_frame,
            text="Show Key",
            variable=self.encrypt_show_key_var,
            command=lambda: self.toggle_show(self.encrypt_key_entry, self.encrypt_show_key_var)
        ).grid(row=1, column=2, padx=5, pady=6, sticky="w")

        # PASSWORD MODE widgets
        ttk.Label(settings_frame, text="Password:").grid(row=2, column=0, padx=10, pady=6, sticky="w")
        self.encrypt_password_entry = ttk.Entry(settings_frame, width=70, show="•")
        self.encrypt_password_entry.grid(row=2, column=1, padx=5, pady=6, sticky="w")

        self.encrypt_show_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            settings_frame,
            text="Show Password",
            variable=self.encrypt_show_password_var,
            command=lambda: self.toggle_show(self.encrypt_password_entry, self.encrypt_show_password_var)
        ).grid(row=2, column=2, padx=5, pady=6, sticky="w")

        ttk.Label(settings_frame, text="Salt (auto-generated in password mode):").grid(
            row=3, column=0, padx=10, pady=6, sticky="w"
        )
        self.encrypt_salt_entry = ttk.Entry(settings_frame, width=70)
        self.encrypt_salt_entry.grid(row=3, column=1, padx=5, pady=6, sticky="w")

        salt_copy_btn = ttk.Button(settings_frame, text="Copy Salt", command=lambda: self.copy_entry(self.encrypt_salt_entry, "Salt copied."))
        salt_copy_btn.grid(row=3, column=2, padx=5, pady=6)

        # Buttons
        btn_frame = ttk.Frame(self.encrypt_tab)
        btn_frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(btn_frame, text="Encrypt", command=self.encrypt_action).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Clear", command=self.clear_encrypt_tab).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Load Message File", command=self.load_encrypt_input).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Save Encrypted Output", command=self.save_encrypt_output).pack(side="left", padx=6)

        # Output
        output_frame = ttk.LabelFrame(self.encrypt_tab, text="Encrypted Output")
        output_frame.pack(fill="both", expand=True, padx=10, pady=8)

        self.encrypt_output = scrolledtext.ScrolledText(
            output_frame, height=10, wrap=tk.WORD, font=("Consolas", 11)
        )
        self.encrypt_output.pack(fill="both", expand=True, padx=8, pady=8)

        bottom_frame = ttk.Frame(self.encrypt_tab)
        bottom_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(bottom_frame, text="Copy Encrypted Output", command=lambda: self.copy_textbox(self.encrypt_output, "Encrypted output copied.")).pack(side="left", padx=6)
        ttk.Button(bottom_frame, text="Copy Key", command=lambda: self.copy_entry(self.encrypt_key_entry, "Key copied.")).pack(side="left", padx=6)
        ttk.Button(bottom_frame, text="Save Key", command=self.save_encrypt_key).pack(side="left", padx=6)
        ttk.Button(bottom_frame, text="Save Salt", command=self.save_encrypt_salt).pack(side="left", padx=6)

        self.toggle_encrypt_mode()
        self.toggle_existing_key()

    # -------------------------
    # DECRYPT TAB
    # -------------------------
    def build_decrypt_tab(self):
        top_frame = ttk.Frame(self.decrypt_tab)
        top_frame.pack(fill="x", padx=10, pady=10)

        # Decryption mode
        mode_frame = ttk.LabelFrame(top_frame, text="Decryption Mode")
        mode_frame.pack(fill="x", pady=5)

        self.decrypt_mode = tk.StringVar(value="key")

        ttk.Radiobutton(
            mode_frame, text="Fernet Key Mode", variable=self.decrypt_mode, value="key",
            command=self.toggle_decrypt_mode
        ).grid(row=0, column=0, padx=10, pady=10, sticky="w")

        ttk.Radiobutton(
            mode_frame, text="Password Mode", variable=self.decrypt_mode, value="password",
            command=self.toggle_decrypt_mode
        ).grid(row=0, column=1, padx=10, pady=10, sticky="w")

        # Token input
        input_frame = ttk.LabelFrame(self.decrypt_tab, text="Encrypted Token")
        input_frame.pack(fill="both", expand=False, padx=10, pady=8)

        self.decrypt_input = scrolledtext.ScrolledText(
            input_frame, height=10, wrap=tk.WORD, font=("Consolas", 11)
        )
        self.decrypt_input.pack(fill="both", expand=True, padx=8, pady=8)

        # Key/Password settings
        settings_frame = ttk.LabelFrame(self.decrypt_tab, text="Key / Password Settings")
        settings_frame.pack(fill="x", padx=10, pady=8)

        ttk.Label(settings_frame, text="Fernet Key:").grid(row=0, column=0, padx=10, pady=6, sticky="w")
        self.decrypt_key_entry = ttk.Entry(settings_frame, width=70, show="•")
        self.decrypt_key_entry.grid(row=0, column=1, padx=5, pady=6, sticky="w")

        self.decrypt_show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            settings_frame,
            text="Show Key",
            variable=self.decrypt_show_key_var,
            command=lambda: self.toggle_show(self.decrypt_key_entry, self.decrypt_show_key_var)
        ).grid(row=0, column=2, padx=5, pady=6, sticky="w")

        ttk.Label(settings_frame, text="Password:").grid(row=1, column=0, padx=10, pady=6, sticky="w")
        self.decrypt_password_entry = ttk.Entry(settings_frame, width=70, show="•")
        self.decrypt_password_entry.grid(row=1, column=1, padx=5, pady=6, sticky="w")

        self.decrypt_show_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            settings_frame,
            text="Show Password",
            variable=self.decrypt_show_password_var,
            command=lambda: self.toggle_show(self.decrypt_password_entry, self.decrypt_show_password_var)
        ).grid(row=1, column=2, padx=5, pady=6, sticky="w")

        ttk.Label(settings_frame, text="Salt (required in password mode):").grid(
            row=2, column=0, padx=10, pady=6, sticky="w"
        )
        self.decrypt_salt_entry = ttk.Entry(settings_frame, width=70)
        self.decrypt_salt_entry.grid(row=2, column=1, padx=5, pady=6, sticky="w")

        ttk.Button(settings_frame, text="Copy Salt", command=lambda: self.copy_entry(self.decrypt_salt_entry, "Salt copied.")).grid(
            row=2, column=2, padx=5, pady=6
        )

        # Buttons
        btn_frame = ttk.Frame(self.decrypt_tab)
        btn_frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(btn_frame, text="Decrypt", command=self.decrypt_action).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Clear", command=self.clear_decrypt_tab).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Load Token File", command=self.load_decrypt_input).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Load Key File", command=self.load_decrypt_key).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Load Salt File", command=self.load_decrypt_salt).pack(side="left", padx=6)

        # Output
        output_frame = ttk.LabelFrame(self.decrypt_tab, text="Decrypted Output")
        output_frame.pack(fill="both", expand=True, padx=10, pady=8)

        self.decrypt_output = scrolledtext.ScrolledText(
            output_frame, height=10, wrap=tk.WORD, font=("Consolas", 11)
        )
        self.decrypt_output.pack(fill="both", expand=True, padx=8, pady=8)

        bottom_frame = ttk.Frame(self.decrypt_tab)
        bottom_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(bottom_frame, text="Copy Decrypted Output", command=lambda: self.copy_textbox(self.decrypt_output, "Decrypted output copied.")).pack(side="left", padx=6)
        ttk.Button(bottom_frame, text="Save Decrypted Output", command=self.save_decrypt_output).pack(side="left", padx=6)

        self.toggle_decrypt_mode()

    # =========================
    # TOGGLES
    # =========================

    def toggle_show(self, entry_widget, bool_var):
        entry_widget.config(show="" if bool_var.get() else "•")

    def toggle_existing_key(self):
        if self.use_existing_key_var.get():
            self.encrypt_key_entry.config(state="normal")
        else:
            self.encrypt_key_entry.delete(0, tk.END)
            self.encrypt_key_entry.config(state="disabled")

    def toggle_encrypt_mode(self):
        mode = self.encrypt_mode.get()

        if mode == "key":
            self.use_existing_key_check.config(state="normal")
            self.toggle_existing_key()

            self.encrypt_password_entry.config(state="disabled")
            self.encrypt_salt_entry.config(state="disabled")
        else:
            self.use_existing_key_check.config(state="disabled")
            self.encrypt_key_entry.config(state="disabled")

            self.encrypt_password_entry.config(state="normal")
            self.encrypt_salt_entry.config(state="normal")

    def toggle_decrypt_mode(self):
        mode = self.decrypt_mode.get()

        if mode == "key":
            self.decrypt_key_entry.config(state="normal")
            self.decrypt_password_entry.config(state="disabled")
            self.decrypt_salt_entry.config(state="disabled")
        else:
            self.decrypt_key_entry.config(state="disabled")
            self.decrypt_password_entry.config(state="normal")
            self.decrypt_salt_entry.config(state="normal")

    # =========================
    # ENCRYPT ACTION
    # =========================

    def encrypt_action(self):
        message = self.encrypt_input.get("1.0", tk.END).rstrip("\n")

        if not message.strip():
            self.set_status("⚠ Please enter a message to encrypt.")
            messagebox.showwarning("Missing Input", "Please enter a message to encrypt.")
            return

        try:
            mode = self.encrypt_mode.get()

            if mode == "key":
                if self.use_existing_key_var.get():
                    key_text = self.encrypt_key_entry.get().strip()
                    if not key_text:
                        self.set_status("⚠ Please enter an existing Fernet key.")
                        messagebox.showwarning("Missing Key", "Please enter an existing Fernet key.")
                        return
                    key = key_text.encode("utf-8")
                else:
                    key = Fernet.generate_key()
                    self.encrypt_key_entry.config(state="normal")
                    self.encrypt_key_entry.delete(0, tk.END)
                    self.encrypt_key_entry.insert(0, key.decode("utf-8"))
                    if not self.use_existing_key_var.get():
                        self.encrypt_key_entry.config(state="disabled")

                token = encrypt_with_key(message, key)

                self.encrypt_output.delete("1.0", tk.END)
                self.encrypt_output.insert(tk.END, token.decode("utf-8"))

                self.encrypt_salt_entry.config(state="normal")
                self.encrypt_salt_entry.delete(0, tk.END)
                self.encrypt_salt_entry.config(state="disabled")

                self.set_status("✅ Message encrypted successfully using Fernet key mode.")

            else:
                password = self.encrypt_password_entry.get()
                if not password:
                    self.set_status("⚠ Please enter a password.")
                    messagebox.showwarning("Missing Password", "Please enter a password.")
                    return

                salt, token = encrypt_with_password(message, password)
                salt_b64 = base64.urlsafe_b64encode(salt).decode("utf-8")

                self.encrypt_output.delete("1.0", tk.END)
                self.encrypt_output.insert(tk.END, token.decode("utf-8"))

                self.encrypt_salt_entry.config(state="normal")
                self.encrypt_salt_entry.delete(0, tk.END)
                self.encrypt_salt_entry.insert(0, salt_b64)

                self.encrypt_key_entry.config(state="normal")
                self.encrypt_key_entry.delete(0, tk.END)
                self.encrypt_key_entry.config(state="disabled")

                self.set_status("✅ Message encrypted successfully using password mode.")

        except Exception as e:
            self.set_status("❌ Encryption failed.")
            messagebox.showerror("Encryption Error", str(e))

    # =========================
    # DECRYPT ACTION
    # =========================

    def decrypt_action(self):
        token = self.decrypt_input.get("1.0", tk.END).rstrip("\n")

        if not token.strip():
            self.set_status("⚠ Please enter an encrypted token.")
            messagebox.showwarning("Missing Input", "Please enter an encrypted token.")
            return

        try:
            mode = self.decrypt_mode.get()

            if mode == "key":
                key_text = self.decrypt_key_entry.get().strip()
                if not key_text:
                    self.set_status("⚠ Please enter a Fernet key.")
                    messagebox.showwarning("Missing Key", "Please enter a Fernet key.")
                    return

                decrypted = decrypt_with_key(token, key_text.encode("utf-8"))

                self.decrypt_output.delete("1.0", tk.END)
                self.decrypt_output.insert(tk.END, decrypted)
                self.set_status("✅ Message decrypted successfully using Fernet key mode.")

            else:
                password = self.decrypt_password_entry.get()
                salt_b64 = self.decrypt_salt_entry.get().strip()

                if not password:
                    self.set_status("⚠ Please enter a password.")
                    messagebox.showwarning("Missing Password", "Please enter a password.")
                    return

                if not salt_b64:
                    self.set_status("⚠ Please enter/load the salt.")
                    messagebox.showwarning("Missing Salt", "Please enter/load the salt.")
                    return

                decrypted = decrypt_with_password(token, password, salt_b64)

                self.decrypt_output.delete("1.0", tk.END)
                self.decrypt_output.insert(tk.END, decrypted)
                self.set_status("✅ Message decrypted successfully using password mode.")

        except InvalidToken:
            self.set_status("❌ Invalid token, wrong key/password, or corrupted data.")
            messagebox.showerror(
                "Decryption Error",
                "Invalid token, wrong key/password, or corrupted encrypted message."
            )
        except Exception as e:
            self.set_status("❌ Decryption failed.")
            messagebox.showerror("Decryption Error", str(e))

    # =========================
    # FILE FUNCTIONS
    # =========================

    def save_text_to_file(self, text, title, default_ext, filetypes):
        if not text.strip():
            self.set_status("⚠ Nothing to save.")
            messagebox.showwarning("Empty", "Nothing to save.")
            return

        file_path = filedialog.asksaveasfilename(
            title=title,
            defaultextension=default_ext,
            filetypes=filetypes
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(text)
            self.set_status(f"✅ Saved: {os.path.basename(file_path)}")

    def load_text_from_file(self, textbox=None, entry=None, title="Open File"):
        file_path = filedialog.askopenfilename(
            title=title,
            filetypes=[("Text Files", "*.txt *.key *.salt"), ("All Files", "*.*")]
        )
        if file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                data = f.read()

            if textbox:
                textbox.delete("1.0", tk.END)
                textbox.insert(tk.END, data)
            elif entry:
                entry.config(state="normal")
                entry.delete(0, tk.END)
                entry.insert(0, data.strip())

            self.set_status(f"✅ Loaded: {os.path.basename(file_path)}")

    # Encrypt tab save/load
    def load_encrypt_input(self):
        self.load_text_from_file(textbox=self.encrypt_input, title="Load Message File")

    def save_encrypt_output(self):
        text = self.encrypt_output.get("1.0", tk.END).strip()
        self.save_text_to_file(text, "Save Encrypted Output", ".txt", [("Text Files", "*.txt")])

    def save_encrypt_key(self):
        key = self.encrypt_key_entry.get().strip()
        self.save_text_to_file(key, "Save Fernet Key", ".key", [("Key Files", "*.key"), ("Text Files", "*.txt")])

    def save_encrypt_salt(self):
        salt = self.encrypt_salt_entry.get().strip()
        self.save_text_to_file(salt, "Save Salt", ".salt", [("Salt Files", "*.salt"), ("Text Files", "*.txt")])

    # Decrypt tab save/load
    def load_decrypt_input(self):
        self.load_text_from_file(textbox=self.decrypt_input, title="Load Encrypted Token")

    def load_decrypt_key(self):
        self.load_text_from_file(entry=self.decrypt_key_entry, title="Load Fernet Key")

    def load_decrypt_salt(self):
        self.load_text_from_file(entry=self.decrypt_salt_entry, title="Load Salt")

    def save_decrypt_output(self):
        text = self.decrypt_output.get("1.0", tk.END).strip()
        self.save_text_to_file(text, "Save Decrypted Output", ".txt", [("Text Files", "*.txt")])

    # =========================
    # CLIPBOARD / CLEAR / STATUS
    # =========================

    def copy_textbox(self, textbox, success_msg):
        text = textbox.get("1.0", tk.END).strip()
        if not text:
            self.set_status("⚠ Nothing to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.set_status(f"📋 {success_msg}")

    def copy_entry(self, entry, success_msg):
        text = entry.get().strip()
        if not text:
            self.set_status("⚠ Nothing to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.set_status(f"📋 {success_msg}")

    def clear_encrypt_tab(self):
        self.encrypt_input.delete("1.0", tk.END)
        self.encrypt_output.delete("1.0", tk.END)

        self.encrypt_key_entry.config(state="normal")
        self.encrypt_key_entry.delete(0, tk.END)
        if not self.use_existing_key_var.get() or self.encrypt_mode.get() != "key":
            self.encrypt_key_entry.config(state="disabled")

        self.encrypt_password_entry.delete(0, tk.END)

        self.encrypt_salt_entry.config(state="normal")
        self.encrypt_salt_entry.delete(0, tk.END)
        if self.encrypt_mode.get() == "key":
            self.encrypt_salt_entry.config(state="disabled")

        self.set_status("🧹 Encrypt tab cleared.")

    def clear_decrypt_tab(self):
        self.decrypt_input.delete("1.0", tk.END)
        self.decrypt_output.delete("1.0", tk.END)
        self.decrypt_key_entry.delete(0, tk.END)
        self.decrypt_password_entry.delete(0, tk.END)
        self.decrypt_salt_entry.delete(0, tk.END)
        self.set_status("🧹 Decrypt tab cleared.")

    def set_status(self, msg):
        self.status_var.set(msg)


# =========================
# RUN APP
# =========================

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFernetApp(root)
    root.mainloop()     