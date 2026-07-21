import argparse
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import getpass
import os
import secrets


SALT_FILE = "salt.salt"
DEFAULT_SALT_SIZE = 16


#Generate a cryptographically secure random salt
def generate_salt(size=DEFAULT_SALT_SIZE):
    return secrets.token_bytes(size)


#Load the previously generated salt from disk
def load_salt():
    with open(SALT_FILE, "rb") as salt_file:
        return salt_file.read()


def save_salt(salt):
    with open(SALT_FILE, "wb") as salt_file:
        salt_file.write(salt)


#Derive a secure 32-byte key from a password and salt
def derive_key(salt, password):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )

    return kdf.derive(password.encode("utf-8"))


def generate_key(password, salt):
    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key)


#Encrypt a file
def encrypt(filename, key):
    cipher = Fernet(key)

    # Read the original file as binary data
    with open(filename, "rb") as input_file:
        file_data = input_file.read()

    # Encrypt the complete file content.
    encrypted_data = cipher.encrypt(file_data)

    # Replace the original content with encrypted data
    with open(filename, "wb") as output_file:
        output_file.write(encrypted_data)

    print("File encrypted successfully")


def decrypt(filename, key):
    cipher = Fernet(key)

    # Read the encrypted file as binary data
    with open(filename, "rb") as input_file:
        encrypted_data = input_file.read()

    try:
        # Verify and decrypt the encrypted file content
        decrypted_data = cipher.decrypt(encrypted_data)
    except InvalidToken:
        print("Invalid password, salt, or file")
        return

    # Replace the encrypted content with the original data
    with open(filename, "wb") as output_file:
        output_file.write(decrypted_data)

    print("File decrypted successfully.")


def main():
    """Parse command-line arguments and run the selected operation"""
    parser = argparse.ArgumentParser(
        description="Scrypt-based file encryption and decryption tool"
    )

    parser.add_argument(
        "file",
        help="Path to the file to encrypt or decrypt",
    )

    # Only one operation can be selected at a time
    operation_group = parser.add_mutually_exclusive_group(required=True)

    operation_group.add_argument(
        "-e",
        "--encrypt",
        action="store_true",
        help="Encrypt the selected file",
    )

    operation_group.add_argument(
        "-d",
        "--decrypt",
        action="store_true",
        help="Decrypt the selected file",
    )

    parser.add_argument(
        "-s",
        "--salt-size",
        type=int,
        default=DEFAULT_SALT_SIZE,
        help="Salt size in bytes used during encryption",
    )

    args = parser.parse_args()
    filename = args.file

    # Ensure that the selected file exists.
    if not os.path.isfile(filename):
        parser.error(f"File does not exist: {filename}")

    if args.salt_size <= 0:
        parser.error("Salt size must be greater than zero")

    if args.encrypt:
        password = getpass.getpass("Enter password for encryption: ")

        # Generate and store a new salt for this encryption key.
        salt = generate_salt(args.salt_size)
        save_salt(salt)

        key = generate_key(password, salt)
        encrypt(filename, key)

    else:
        # Decryption requires the original salt file.
        if not os.path.isfile(SALT_FILE):
            parser.error(
                f"Salt file '{SALT_FILE}' was not found "
                "The file cannot be decrypted without the original salt"
            )

        password = getpass.getpass(
            "Enter the password used for encryption: "
        )

        salt = load_salt()
        key = generate_key(password, salt)
        decrypt(filename, key)


if __name__ == "__main__":
    main()