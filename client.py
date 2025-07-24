import socket
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HOST = '127.0.0.1'
PORT = 65432

# 1. Generate X25519 keypair for the client
private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()
public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

print('\n================ CLIENT STARTED ================')
print('--- Key Generation ---')
print(f'Client public key:           {public_bytes.hex()}\n')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # 2. Send the client's public key to the server
    print('--- Key Exchange ---')
    s.sendall(public_bytes)
    print(f'Sent client public key:      {public_bytes.hex()}')

    # 3. Receive the server's public key
    server_pub_bytes = s.recv(32)
    print(f"Received server's public key: {server_pub_bytes.hex()}\n")

    # 4. Derive the shared secret using ECDH
    server_public_key = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared_secret = private_key.exchange(server_public_key)
    print('--- Shared Secret ---')
    print(f'Derived shared secret:       {shared_secret.hex()}\n')

    # 5. Derive the AES-256 key using HKDF
    print('--- Key Derivation ---')
    salt = os.urandom(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data',
    )
    key = hkdf.derive(shared_secret)
    print(f'Generated salt:              {salt.hex()}')
    print(f'Derived AES-256 key:         {key.hex()}\n')

    # 6. Send the salt to the server
    s.sendall(salt)

    # 7. Get the message to send
    message = input('Enter message to send: ').encode()

    # 8. Encrypt the message using AES-256-GCM
    print('\n--- Message Encryption ---')
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, b'')
    print(f'Generated nonce:             {nonce.hex()}')
    print(f'Ciphertext:                  {ciphertext.hex()}\n')

    # 9. Send the nonce, ciphertext length, and ciphertext to the server
    s.sendall(nonce)
    s.sendall(len(ciphertext).to_bytes(2, 'big'))
    s.sendall(ciphertext)
    print('Message sent securely! The server should print the decrypted message.')
    print('==========================================================\n') 