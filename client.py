import socket  # For network communication
import os  # For generating random salt/nonce
from cryptography.hazmat.primitives.asymmetric import x25519  # For X25519 key exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # For key derivation
from cryptography.hazmat.primitives import hashes  # For HKDF hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # For AES-GCM encryption/decryption
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # For public key serialization

HOST = '127.0.0.1'  # Server address (localhost)
PORT = 65432         # Server port

# 1. Generate X25519 keypair for the client
private_key = x25519.X25519PrivateKey.generate()  # Client's private key
public_key = private_key.public_key()             # Client's public key
public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)  # Serialize public key to bytes

print('\n================ CLIENT STARTED ================')
print('--- Key Generation ---')
print(f'Client public key:           {public_bytes.hex()}\n')

# Create a TCP socket and connect to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))  # Connect to server

    # 2. Send the client's public key to the server
    print('--- Key Exchange ---')
    s.sendall(public_bytes)  # Send client's public key
    print(f'Sent client public key:      {public_bytes.hex()}')

    # 3. Receive the server's public key
    server_pub_bytes = s.recv(32)  # Receive server's public key
    print(f"Received server's public key: {server_pub_bytes.hex()}\n")

    # 4. Derive the shared secret using ECDH
    server_public_key = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)  # Deserialize server's public key
    shared_secret = private_key.exchange(server_public_key)  # Perform ECDH to get shared secret
    print('--- Shared Secret ---')
    print(f'Derived shared secret:       {shared_secret.hex()}\n')

    # 5. Derive the AES-256 key using HKDF
    print('--- Key Derivation ---')
    salt = os.urandom(16)  # Generate random 16-byte salt
    hkdf = HKDF(
        algorithm=hashes.SHA256(),  # Use SHA-256
        length=32,                  # 32 bytes = 256 bits
        salt=salt,                  # Use generated salt
        info=b'handshake data',     # Context info
    )
    key = hkdf.derive(shared_secret)  # Derive AES key
    print(f'Generated salt:              {salt.hex()}')
    print(f'Derived AES-256 key:         {key.hex()}\n')

    # 6. Send the salt to the server
    s.sendall(salt)  # Send salt

    # 7. Get the message to send
    message = input('Enter message to send: ').encode()  # Get user input and encode to bytes

    # 8. Encrypt the message using AES-256-GCM
    print('\n--- Message Encryption ---')
    aesgcm = AESGCM(key)  # Create AESGCM object with derived key
    nonce = os.urandom(12)  # Generate random 12-byte nonce
    ciphertext = aesgcm.encrypt(nonce, message, b'')  # Encrypt the message
    print(f'Generated nonce:             {nonce.hex()}')
    print(f'Ciphertext:                  {ciphertext.hex()}\n')

    # 9. Send the nonce, ciphertext length, and ciphertext to the server
    s.sendall(nonce)  # Send nonce
    s.sendall(len(ciphertext).to_bytes(2, 'big'))  # Send ciphertext length (2 bytes)
    s.sendall(ciphertext)  # Send ciphertext
    print('Message sent securely! The server should print the decrypted message.')
    print('==========================================================\n') 