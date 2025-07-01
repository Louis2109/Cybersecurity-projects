"""
File Encryptor: Encrypt and Decrypt Any File (including images) using AES

Author: Louis2109

=======================================
DOCUMENTATION
=======================================

1. What does this tool do?
--------------------------
- Encrypts any file (image, PDF, document, etc.) securely using AES encryption.
- Decrypts previously encrypted files with the correct password.
- All encryption is password-based and uses a unique salt and IV for each file.

2. How does it work?
---------------------
- The tool derives a 256-bit key from your password using PBKDF2 (with a random salt).
- It uses AES in GCM mode (for both encryption and authentication).
- The encrypted file stores: [salt | iv | ciphertext | tag].
- To decrypt, the tool reads the salt and iv, regenerates the key from your password, and restores your file.

3. How to use?
---------------
- Run this script in your terminal: python file_encryptor.py
- Choose to encrypt or decrypt a file.
- Provide file paths and your password as prompted.
- Encrypted files will have '.enc' extension by convention.

4. Security Notes
------------------
- Never lose your password - without it, decryption is impossible!
- Each file uses a unique salt and IV for maximum security.

Dependencies:
-------------
- pycryptodome (install with: pip install pycryptodome)

=======================================
"""

import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Constants
SALT_SIZE = 16        # 16 bytes for salt
KEY_SIZE = 32         # 32 bytes = 256 bits for AES-256
IV_SIZE = 12          # 12 bytes for GCM IV
TAG_SIZE = 16         # 16 bytes for GCM tag
PBKDF2_ITER = 200000  # Iterations for PBKDF2

def encrypt_file(input_path, output_path, password):
    """Encrypts a file with AES-GCM. Output is: [salt][iv][tag][ciphertext]."""
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITER)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    # Encrypt file in chunks
    ciphertext = b''
    with open(input_path, 'rb') as infile:
        while True:
            chunk = infile.read(1024 * 1024)  # 1 MB at a time
            if not chunk:
                break
            ciphertext += cipher.encrypt(chunk)
    tag = cipher.digest()

    with open(output_path, 'wb') as outfile:
        outfile.write(salt + iv + tag + ciphertext)

def decrypt_file(input_path, output_path, password):
    """Decrypts a file previously encrypted with this tool."""
    with open(input_path, 'rb') as infile:
        salt = infile.read(SALT_SIZE)
        iv = infile.read(IV_SIZE)
        tag = infile.read(TAG_SIZE)
        ciphertext = infile.read()

    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITER)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        # Decrypt in chunks (if needed, for large files)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        print("Decryption failed! Incorrect password or corrupted file.")
        return False

    with open(output_path, 'wb') as outfile:
        outfile.write(plaintext)
    return True

def print_menu():
    print("\n===== File Encryptor =====")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. About / Documentation")
    print("4. Exit")

def main():
    while True:
        print_menu()
        choice = input("Select an option: ").strip()
        if choice == '1':
            in_path = input("Enter the path of the file to encrypt: ").strip()
            if not os.path.isfile(in_path):
                print("File not found.")
                continue
            # Générer automatiquement le nom du fichier chiffré
            out_path = in_path + ".enc"
            password = input("Enter password (remember this!): ")
            encrypt_file(in_path, out_path, password)
            print(f"File encrypted and saved as {out_path}")
        elif choice == '2':
            in_path = input("Enter the path of the encrypted file: ").strip()
            if not os.path.isfile(in_path):
                print("File not found.")
                continue
            # Générer automatiquement le nom du fichier déchiffré
            if in_path.endswith(".enc"):
                out_path = in_path[:-4]  # Retire ".enc"
            else:
                out_path = in_path + ".decrypted"
            password = input("Enter password: ")
            success = decrypt_file(in_path, out_path, password)
            if success:
                print(f"File decrypted and saved as {out_path}")
        elif choice == '3':
            print(__doc__)
        elif choice == '4':
            print("Goodbye.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()