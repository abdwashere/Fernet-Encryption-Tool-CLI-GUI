from cryptography.fernet import Fernet

def encrypt_message():
    message = input("Enter the message to encrypt: ").encode()

    # Generate a new key
    key = Fernet.generate_key()
    cipher = Fernet(key)

    # Encrypt the message
    token = cipher.encrypt(message)

    print("\n=== ENCRYPTED OUTPUT ===")
    print("Encrypted Message:", token.decode())
    print("Decryption Key:", key.decode())
    print("\nSave both the encrypted message and the key safely.")


def decrypt_message():
    token = input("Enter the encrypted message: ").encode()
    key = input("Enter the decryption key: ").encode()

    try:
        cipher = Fernet(key)
        message = cipher.decrypt(token)
        print("\n=== DECRYPTED OUTPUT ===")
        print("Original Message:", message.decode())
    except Exception:
        print("\n[ERROR] Invalid key or corrupted encrypted message.")


def main():
    while True:
        print("\n===== FERNET ENCRYPTION TOOL =====")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")

        choice = input("Choose an option (1/2/3): ")

        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            print("Exiting program...")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()