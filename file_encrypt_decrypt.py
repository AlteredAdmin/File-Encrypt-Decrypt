from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding
import os
import base64


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secret key from the password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(file_path: str, password: str):
    """Encrypts a file using the provided password."""
    # Generate a random salt
    salt = os.urandom(16)
    key = derive_key(password, salt)

    with open(file_path, 'rb') as f:
        data = f.read()

    # Padding the data to be compatible with the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Generate a random initialization vector
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the salt, iv, and encrypted data to the file
    with open(file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)


def decrypt_file(file_path: str, password: str):
    """Decrypts a file using the provided password."""
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(file_path, 'wb') as f:
        f.write(decrypted_data)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using a password.")
    parser.add_argument("file", help="The path to the file to encrypt/decrypt.")
    parser.add_argument("password", help="The password to use for encryption/decryption.")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt the file. Default is to encrypt.")

    args = parser.parse_args()

    if args.decrypt:
        decrypt_file(args.file, args.password)
    else:
        encrypt_file(args.file, args.password)
