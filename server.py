import socket
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HOST = '127.0.0.1'
PORT = 65432

# 1. Generate X25519 keypair for the server
private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()
public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

print('\n================ SERVER STARTED ================')
print(f'Server listening on {HOST}:{PORT}\n')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print('---------------- CONNECTION ESTABLISHED ----------------')
        print(f'Connected by: {addr}\n')

        # 2. Receive the client's public key (32 bytes for X25519)
        client_pub_bytes = conn.recv(32)
        print('--- Key Exchange ---')
        print(f"Received client's public key: {client_pub_bytes.hex()}")

        # 3. Send the server's public key to the client
        conn.sendall(public_bytes)
        print(f"Sent server's public key:    {public_bytes.hex()}\n")

        # 4. Derive the shared secret using ECDH
        client_public_key = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared_secret = private_key.exchange(client_public_key)
        print('--- Shared Secret ---')
        print(f"Derived shared secret:       {shared_secret.hex()}\n")

        # 5. Receive the salt for HKDF from the client
        salt = conn.recv(16)
        print('--- Key Derivation ---')
        print(f"Received salt:               {salt.hex()}")

        # 6. Derive the AES-256 key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'handshake data',
        )
        key = hkdf.derive(shared_secret)
        print(f"Derived AES-256 key:         {key.hex()}\n")

        # 7. Receive the nonce (12 bytes for AES-GCM)
        nonce = conn.recv(12)
        print('--- Message Reception ---')
        print(f"Received nonce:              {nonce.hex()}")

        # 8. Receive the ciphertext length (2 bytes, big endian)
        ct_len = int.from_bytes(conn.recv(2), 'big')

        # 9. Receive the ciphertext
        ciphertext = conn.recv(ct_len)
        print(f"Received ciphertext:         {ciphertext.hex()}\n")

        # 10. Decrypt the message
        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, b'')
            print('--- Decryption Result ---')
            print('Decrypted message from client:')
            print(f'    "{plaintext.decode()}"\n')
            print('SUCCESS: Secure key exchange and message decryption worked!')
            print('==========================================================\n')
        except Exception as e:
            print('Decryption failed:', e) 