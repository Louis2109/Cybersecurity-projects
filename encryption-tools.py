import os
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from PIL import Image
import io
import numpy as np

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
    print("4. File Encryption (AES-GCM):")
    print("   - Encrypts any file securely using AES in GCM mode (authenticated encryption).")
    print("   - Password-based key derivation (PBKDF2), unique salt and IV per file.")
    print("   - Encrypted files have '.enc' extension by convention.\n")

# =================== Caesar Cipher ===================

def caesar_cipher(text, shift, mode='encrypt'):
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

# =================== AES Text Encryption ===================

def aes_encrypt(plaintext, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    result = base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()
    return result

def aes_decrypt(encoded_data, password):
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
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key_pem):
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(encoded_data, private_key_pem):
    try:
        key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = base64.b64decode(encoded_data)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# =================== File Encryption (AES-GCM) ===================

SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 12
TAG_SIZE = 16
PBKDF2_ITER = 200000

def create_default_image(width=800, height=600):
    # Créer une image en dégradé bleu-vert
    array = np.zeros((height, width, 3), dtype=np.uint8)
    for i in range(height):
        for j in range(width):
            array[i, j] = [
                int(255 * (1 - i/height)),  # Blue channel
                int(255 * (j/width)),       # Green channel
                100                         # Red channel
            ]
    
    # Convertir le tableau numpy en image PIL
    image = Image.fromarray(array)
    return image

def data_to_image(data):
    # Créer l'image de base
    img = create_default_image()
    
    # Convertir les données en bytes si ce n'est pas déjà le cas
    if not isinstance(data, bytes):
        data = data.encode()
    
    # Ajouter la taille des données comme metadata
    size_bytes = len(data).to_bytes(8, byteorder='big')
    final_data = size_bytes + data
    
    # Convertir l'image en bytes
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_bytes = img_byte_arr.getvalue()
    
    # Concatener les données à la fin de l'image
    return img_bytes + final_data

def image_to_data(image_path):
    with open(image_path, 'rb') as f:
        data = f.read()
    
    # Trouver la fin des données PNG
    png_end = data.rfind(b'IEND') + 8
    
    # Extraire les données après l'image
    encrypted_data = data[png_end:]
    
    # Extraire la taille des données originales
    size = int.from_bytes(encrypted_data[:8], byteorder='big')
    
    # Retourner les données originales
    return encrypted_data[8:8+size]

def encrypt_file(input_path, output_path, password):
    salt = get_random_bytes(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITER)
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    # Lire le fichier d'entrée
    with open(input_path, 'rb') as infile:
        file_data = infile.read()
    # Chiffrer les données
    ciphertext = cipher.encrypt(file_data)
    tag = cipher.digest()    
    # Préparer les données finales
    final_data = salt + iv + tag + ciphertext    
    # Convertir en image
    image_data = data_to_image(final_data)   
    # Sauvegarder l'image
    with open(output_path, 'wb') as outfile:
        outfile.write(image_data)


def decrypt_file(input_path, output_path, password):
    try:
        # Extraire les données de l'image
        encrypted_data = image_to_data(input_path)
        
        # Extraire les composants
        salt = encrypted_data[:SALT_SIZE]
        iv = encrypted_data[SALT_SIZE:SALT_SIZE+IV_SIZE]
        tag = encrypted_data[SALT_SIZE+IV_SIZE:SALT_SIZE+IV_SIZE+TAG_SIZE]
        ciphertext = encrypted_data[SALT_SIZE+IV_SIZE+TAG_SIZE:]
        
        # Déchiffrer
        key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITER)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            print("Decryption failed! Incorrect password or corrupted file.")
            return False

  
        # Récupérer l'extension d'origine du fichier
        original_extension = os.path.splitext(input_path)[1]

        # Enregistrer le fichier déchiffré avec l'extension d'origine
        output_path = os.path.splitext(input_path)[0] + original_extension

        # Sauvegarder le fichier déchiffré
        with open(output_path, 'wb') as outfile:
            outfile.write(plaintext)
        return True
        
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return False
# =================== Menus ===================

def text_encryption_menu():
    rsa_keys = {}
    while True:
        print("\n--- Text Encryption/Decryption ---")
        print("1. Caesar Cipher")
        print("2. AES Encryption")
        print("3. RSA Encryption (Advanced)")
        print("4. Back to main menu")
        choice = input("Select an option: ").strip()
        if choice == "1":
            caesar_menu()
        elif choice == "2":
            aes_menu()
        elif choice == "3":
            rsa_menu(rsa_keys)
        elif choice == "4":
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
    print("5. Back")
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

def file_encryption_menu():
    while True:
        print("\n--- File Encryption/Decryption ---")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Back to main menu")
        choice = input("Select an option: ").strip()
        if choice == '1':
            in_path = input("Enter the path of the file to encrypt (or drop the file in the terminal): ").strip()
            if not os.path.isfile(in_path):
                print("File not found.")
                continue
            out_path = in_path + ".png"
            password = input("Enter password (remember this!): ")
            encrypt_file(in_path, out_path, password)
            print(f"File encrypted and saved as {out_path}")
        elif choice == '2':
            in_path = input("Enter the path of the encrypted file: ").strip()
            if not os.path.isfile(in_path):
                print("File not found.")
                continue
            
            password = input("Enter password: ")
            success = decrypt_file(in_path, out_path, password)
            if success:
                print(f"File decrypted and saved as {out_path}")
        elif choice == '3':
            break
        else:
            print("Invalid option.")

def main_menu():
    while True:
        print("\n===== Encryption Tool =====")
        print("1. Text Encryption/Decryption")
        print("2. File Encryption/Decryption")
        print("3. Documentation")
        print("4. Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            text_encryption_menu()
        elif choice == "2":
            file_encryption_menu()
        elif choice == "3":
            print_documentation()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main_menu()