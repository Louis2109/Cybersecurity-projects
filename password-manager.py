"""
Simple Password Manager (Command Line)

Features:
- Stores passwords securely (AES encryption, PBKDF2-derived key)
- Add, get, delete, and list password entries
- All data kept in a single encrypted file (passwords.dat)
- Random password generator included

Dependencies:
- pycryptodome (install with: pip install pycryptodome)
"""

import os
import json
from getpass import getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

DATA_FILE = "passwords.dat"
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 12
PBKDF2_ITER = 200_000

def derive_key(master_password, salt):
    return PBKDF2(master_password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITER)

def encrypt_data(data, master_password):
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(master_password, salt)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return b64encode(salt + iv + tag + ciphertext).decode()

def decrypt_data(enc_data, master_password):
    raw = b64decode(enc_data)
    salt = raw[:SALT_SIZE]
    iv = raw[SALT_SIZE:SALT_SIZE+IV_SIZE]
    tag = raw[SALT_SIZE+IV_SIZE:SALT_SIZE+IV_SIZE+16]
    ciphertext = raw[SALT_SIZE+IV_SIZE+16:]
    key = derive_key(master_password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data.decode()
    except Exception:
        return None

def load_vault(master_password):
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'r') as f:
        enc_data = f.read()
    data = decrypt_data(enc_data, master_password)
    if data is None:
        print("Incorrect master password or corrupted data file.")
        exit(1)
    return json.loads(data)

def save_vault(vault, master_password):
    data = json.dumps(vault)
    enc_data = encrypt_data(data, master_password)
    with open(DATA_FILE, 'w') as f:
        f.write(enc_data)

def generate_password(length=16):
    import string, random
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

def main():
    print("=== Simple Password Manager ===")
    master_password = getpass("Enter master password: ")
    vault = load_vault(master_password)

    while True:
        print("\nOptions: add | get | delete | list | gen | quit")
        cmd = input("Command: ").strip().lower()
        if cmd == "add":
            site = input("Site name: ").strip()
            username = input("Username: ").strip()
            passwd = getpass("Password (leave blank to generate): ")
            if not passwd:
                passwd = generate_password()
                print(f"Generated password: {passwd}")
            vault[site] = {"username": username, "password": passwd}
            save_vault(vault, master_password)
            print("Saved.")
        elif cmd == "get":
            site = input("Site name: ").strip()
            entry = vault.get(site)
            if entry:
                print(f"Username: {entry['username']}\nPassword: {entry['password']}")
            else:
                print("No entry found.")
        elif cmd == "delete":
            site = input("Site name: ").strip()
            if site in vault:
                del vault[site]
                save_vault(vault, master_password)
                print("Deleted.")
            else:
                print("No entry found.")
        elif cmd == "list":
            if vault:
                for site in vault:
                    print(f"- {site}")
            else:
                print("Vault is empty.")
        elif cmd == "gen":
            length = input("Length (default 16): ")
            try:
                length = int(length)
            except:
                length = 16
            print(f"Random password: {generate_password(length)}")
        elif cmd == "quit":
            print("Goodbye.")
            break
        else:
            print("Unknown command.")

if __name__ == "__main__":
    main()