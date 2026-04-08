# Fernet-Encryption-Tool-CLI-GUI
Python files that provides a simple but highly secure command-line interface and a graphical user interface for Symmetric Encryption using the cryptography library. It specifically uses Fernet, which is an implementation of AES (Advanced Encryption Standard) in CBC mode with a 128-bit key.
Generates a unique 16-byte salt for every password-based session to prevent Rainbow Table attacks in GUI file.
Make sure to save the generated "Decryption Key" and the "Encrypted Message." If you lose the key, you cannot recover the message.

CLI file:
simple cli program to encrypt and decrypt messages

GUI file:
Password Mode: Best for memorizing a secret. Requires the Salt to decrypt later.
Key Mode: Generates a random, high-entropy Fernet key.


Prerequisites
Before running the script, ensure you have the `cryptography` library installed:
```bash
pip install cryptography

git clone https://github.com/abdwashere/Fernet-Encryption-Tool-CLI-GUI.git
cd Fernet-Encryption-Tool-CLI-GUI

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/99597c7b-0c3e-4fa9-940a-3aef47e3c6ef" />
