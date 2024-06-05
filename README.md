# File Encrypt Decrypt

### Libraries and Dependencies
- `cryptography.hazmat.primitives.kdf.pbkdf2` for key derivation using PBKDF2.
- `cryptography.hazmat.primitives` for cryptographic primitives such as hashes and padding.
- `cryptography.hazmat.backends` for default cryptographic backend.
- `cryptography.hazmat.primitives.ciphers` for AES encryption and decryption.
- `os` for generating random values.

### Key Derivation Function
```python
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
```
- **Purpose**: This function generates a cryptographic key from the password using PBKDF2 (Password-Based Key Derivation Function 2).
- **Salt**: A random salt ensures the same password produces different keys, enhancing security.
- **Iterations**: More iterations increase the time to derive the key, making brute-force attacks more difficult.

### Encryption
```python
def encrypt_file(file_path: str, password: str):
    """Encrypts a file using the provided password."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    
    with open(file_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)
```
- **Salt**: Generated and stored at the beginning of the file.
- **Key Derivation**: Uses the password and salt to generate the key.
- **Data Reading**: Reads the content of the file to be encrypted.
- **Padding**: Ensures the data is a multiple of the AES block size (required by the encryption algorithm).
- **IV (Initialization Vector)**: Randomly generated and used to ensure different ciphertexts for the same plaintext.
- **Encryption**: Uses AES in CBC mode to encrypt the padded data.
- **Output**: Writes the salt, IV, and encrypted data to the file.

### Decryption
```python
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

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(file_path, 'wb') as f:
        f.write(decrypted_data)
```
- **Reading Salt and IV**: Extracts the salt and IV from the beginning of the file.
- **Key Derivation**: Uses the extracted salt and password to regenerate the key.
- **Decryption**: Uses AES in CBC mode to decrypt the data.
- **Unpadding**: Removes the padding added during encryption.
- **Output**: Writes the decrypted data back to the file.

### Command-Line Interface
```python
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
```
- **argparse**: Used to parse command-line arguments.
- **Arguments**:
  - `file`: The path to the file to encrypt or decrypt.
  - `password`: The password used for encryption/decryption.
  - `--decrypt`: A flag to indicate decryption. If not provided, the default action is encryption.
- **Execution**: Calls the appropriate function (encrypt or decrypt) based on the provided arguments.
