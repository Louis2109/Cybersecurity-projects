import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA

# =================== Documentation ===================

def print_documentation():
    print("\n=== ENCRYPTION ALGORITHMS DOCUMENTATION ===\n")
    print("1. Caesar Cipher:")
    print("   - Type: Classical, symmetric substitution cipher.")
    print("   - Principle: Shifts each letter in the plaintext by a fixed number (the key) within the alphabet.")
    print("   - Example: shift 3, 'A' -> 'D', 'B' -> 'E'.")
    print("   - Weakness: Very easy to break by brute force or frequency analysis.\n")
    print("2. AES (Advanced Encryption Standard):")
    print("   - Type: Modern, symmetric block cipher.")
    print("   - Principle: Encrypts data in blocks (128-bit) using the same secret key for encryption and decryption.")
    print("   - Common key sizes: 128, 192, 256 bits.")
    print("   - Secure and widely used in industry.\n")
    print("3. RSA:")
    print("   - Type: Asymmetric encryption (public/private key pair).")
    print("   - Principle: Public key encrypts data, private key decrypts. Based on the difficulty of factoring large numbers.")
    print("   - Use case: Secure key exchange, digital signatures.")
    print("   - Slower than symmetric encryption, used for small data.\n")

# =================== Caesar Cipher ===================

def caesar_cipher(text, shift, mode='encrypt'):
    """
    Encrypts or decrypts text using the Caesar cipher.
    Encryption: shift each letter forward by 'shift'.
    Decryption: shift each letter backward by 'shift'.
    """
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            if mode == 'encrypt':
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            result += char
    return result

# =================== AES Encryption ===================

def aes_encrypt(plaintext, password):
    """
    Encrypts text using AES (symmetric block cipher).
    - Derives a 256-bit key from the password.
    - Uses GCM mode for authenticated encryption.
    """
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    result = base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()
    return result

def aes_decrypt(encoded_data, password):
    """
    Decrypts AES-encrypted text.
    - Extracts salt, nonce, tag, ciphertext.
    - Derives the same key from the password and salt.
    """
    try:
        data = base64.b64decode(encoded_data)
        salt = data[:16]
        nonce = data[16:32]
        tag = data[32:48]
        ciphertext = data[48:]
        key = PBKDF2(password, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# =================== RSA Encryption ===================

def generate_rsa_keys():
    """
    Generates RSA public and private keys.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key_pem):
    """
    Encrypts text using RSA public key.
    """
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(encoded_data, private_key_pem):
    """
    Decrypts RSA-encrypted text using private key.
    """
    try:
        key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = base64.b64decode(encoded_data)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# =================== Menu ===================

def main_menu():
    rsa_keys = {}
    while True:
        print("\n--- Text Encryption/Decryption Tool ---")
        print("1. Caesar Cipher")
        print("2. AES Encryption")
        print("3. RSA Encryption (Advanced)")
        print("4. Documentation")
        print("5. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            caesar_menu()
        elif choice == "2":
            aes_menu()
        elif choice == "3":
            rsa_menu(rsa_keys)
        elif choice == "4":
            print_documentation()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

def caesar_menu():
    print("\n-- Caesar Cipher --")
    mode = input("Encrypt or Decrypt? (e/d): ").strip().lower()
    if mode not in ('e', 'd'):
        print("Invalid choice.")
        return
    try:
        shift = int(input("Enter shift value (integer): "))
    except ValueError:
        print("Invalid shift value.")
        return
    text = input("Enter your text: ")
    result = caesar_cipher(text, shift, mode='encrypt' if mode == 'e' else 'decrypt')
    print(f"Result: {result}")

def aes_menu():
    print("\n-- AES Encryption --")
    mode = input("Encrypt or Decrypt? (e/d): ").strip().lower()
    password = input("Enter password (keep it secret and remember it): ")
    if mode == 'e':
        plaintext = input("Enter your text: ")
        encrypted = aes_encrypt(plaintext, password)
        print(f"Encrypted (save this!): {encrypted}")
    elif mode == 'd':
        encrypted = input("Enter the encrypted text: ")
        decrypted = aes_decrypt(encrypted, password)
        print(f"Decrypted: {decrypted}")
    else:
        print("Invalid choice.")

def rsa_menu(rsa_keys):
    print("\n-- RSA Encryption (Advanced) --")
    print("1. Generate new key pair")
    print("2. Encrypt text")
    print("3. Decrypt text")
    print("4. Show public key")
    print("5. Back to main menu")
    subchoice = input("Select an option: ").strip()
    if subchoice == "1":
        priv, pub = generate_rsa_keys()
        rsa_keys['private'] = priv
        rsa_keys['public'] = pub
        print("New RSA key pair generated.")
    elif subchoice == "2":
        if 'public' not in rsa_keys:
            print("Generate a key pair first.")
            return
        plaintext = input("Enter your text: ")
        encrypted = rsa_encrypt(plaintext, rsa_keys['public'])
        print(f"Encrypted (save this!): {encrypted}")
    elif subchoice == "3":
        if 'private' not in rsa_keys:
            print("Generate a key pair first.")
            return
        encrypted = input("Enter the encrypted text: ")
        decrypted = rsa_decrypt(encrypted, rsa_keys['private'])
        print(f"Decrypted: {decrypted}")
    elif subchoice == "4":
        if 'public' not in rsa_keys:
            print("Generate a key pair first.")
            return
        print(f"Public Key:\n{rsa_keys['public'].decode()}")
    elif subchoice == "5":
        return
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main_menu()