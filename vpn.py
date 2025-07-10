"""
Simple VPN-like Encrypted Proxy (Educational Demo)

Features:
- Forwards TCP data from a local port to a remote server with AES encryption.
- Can run as a server (relay) or client (proxy).
- Uses a pre-shared key (PSK) for AES encryption.

Dependencies:
    pip install pycryptodome

Usage:
    # Start relay server on remote host:
    python simple_vpn.py server <listen_port> <passkey>

    # Start client on local machine:
    python simple_vpn.py client <local_listen_port> <relay_host> <relay_port> <target_host> <target_port> <passkey>
"""

import socket
import threading
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

BUFFER_SIZE = 4096

def derive_key(psk):
    return hashlib.sha256(psk.encode()).digest()

def pad(data):
    # PKCS7 padding for AES
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext))
    return iv + ct

def decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return unpad(pt)

def handle_client(client_sock, target_host, target_port, key):
    try:
        server_sock = socket.create_connection((target_host, target_port))
    except Exception as e:
        print(f"Connection to {target_host}:{target_port} failed: {e}")
        client_sock.close()
        return

    def forward(src, dst, encrypting):
        try:
            while True:
                data = src.recv(BUFFER_SIZE)
                if not data:
                    break
                if encrypting:
                    out = encrypt(key, data)
                else:
                    try:
                        out = decrypt(key, data)
                    except:
                        break
                dst.sendall(out)
        except:
            pass
        finally:
            src.close()
            dst.close()

    threading.Thread(target=forward, args=(client_sock, server_sock, True)).start()
    threading.Thread(target=forward, args=(server_sock, client_sock, False)).start()

def vpn_server(listen_port, key):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', listen_port))
    s.listen(5)
    print(f"VPN relay server listening on port {listen_port}")
    while True:
        client_sock, addr = s.accept()
        # Get target address/port from client (first message, not encrypted for simplicity)
        header = client_sock.recv(256).decode().strip()
        if ':' not in header:
            client_sock.close()
            continue
        target_host, target_port = header.split(':')
        target_port = int(target_port)
        print(f"Connection from {addr} to {target_host}:{target_port}")
        handle_client(client_sock, target_host, target_port, key)

def vpn_client(local_port, relay_host, relay_port, target_host, target_port, key):
    def handle_local_client(local_sock):
        try:
            relay_sock = socket.create_connection((relay_host, relay_port))
            # Send target info in clear (for demo)
            relay_sock.sendall(f"{target_host}:{target_port}".encode().ljust(256, b' '))
        except Exception as e:
            print(f"Connection to relay server failed: {e}")
            local_sock.close()
            return

        def forward(src, dst, encrypting):
            try:
                while True:
                    data = src.recv(BUFFER_SIZE)
                    if not data:
                        break
                    if encrypting:
                        out = encrypt(key, data)
                    else:
                        try:
                            out = decrypt(key, data)
                        except:
                            break
                    dst.sendall(out)
            except:
                pass
            finally:
                src.close()
                dst.close()

        threading.Thread(target=forward, args=(local_sock, relay_sock, True)).start()
        threading.Thread(target=forward, args=(relay_sock, local_sock, False)).start()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', local_port))
    s.listen(5)
    print(f"VPN client listening on localhost:{local_port}")
    while True:
        local_sock, addr = s.accept()
        print(f"Local connection from {addr}")
        threading.Thread(target=handle_local_client, args=(local_sock,)).start()

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    mode = sys.argv[1]
    if mode == "server" and len(sys.argv) == 4:
        listen_port = int(sys.argv[2])
        psk = sys.argv[3]
        key = derive_key(psk)
        vpn_server(listen_port, key)
    elif mode == "client" and len(sys.argv) == 7:
        local_port = int(sys.argv[2])
        relay_host = sys.argv[3]
        relay_port = int(sys.argv[4])
        target_host = sys.argv[5]
        target_port = int(sys.argv[6])
        psk = sys.argv[7]
        key = derive_key(psk)
        vpn_client(local_port, relay_host, relay_port, target_host, target_port, key)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
# filepath: c:\Users\Nkenf\Desktop\Projet\Cybersecurity-project\vpn.py