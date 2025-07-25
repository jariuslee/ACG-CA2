import socket  # For network communication
import os  # For generating random salt/nonce
from cryptography.hazmat.primitives.asymmetric import x25519  # For X25519 key exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # For key derivation
from cryptography.hazmat.primitives import hashes  # For HKDF hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # For AES-GCM encryption/decryption
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # For public key serialization
from cryptography.hazmat.primitives.asymmetric import ed25519  # For Ed25519 digital signatures
import time  # For timestamp

HOST = '127.0.0.1'  # Server address (localhost)
PORT = 65432         # Server port

# 1. Generate X25519 keypair for the client (for key exchange)
private_key = x25519.X25519PrivateKey.generate()  # Client's private key
public_key = private_key.public_key()             # Client's public key
public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)  # Serialize public key to bytes

# 2. Generate Ed25519 keypair for digital signatures
signing_key = ed25519.Ed25519PrivateKey.generate()  # Client's Ed25519 private key
verify_key = signing_key.public_key()               # Client's Ed25519 public key
verify_bytes = verify_key.public_bytes(Encoding.Raw, PublicFormat.Raw)  # 32 bytes

print('\n================ CLIENT STARTED ================')
print('--- Key Generation ---')
print(f'Client public key (X25519):  {public_bytes.hex()}')
print(f'Client public key (Ed25519): {verify_bytes.hex()}\n')

# Create a TCP socket and connect to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))  # Connect to server

    # 3. Send the client's X25519 public key to the server
    print('--- Key Exchange ---')
    s.sendall(public_bytes)  # Send client's public key
    print(f'Sent client public key:      {public_bytes.hex()}')

    # 4. Receive the server's public key
    server_pub_bytes = s.recv(32)  # Receive server's public key
    print(f"Received server's public key: {server_pub_bytes.hex()}\n")

    # 5. Derive the shared secret using ECDH
    server_public_key = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)  # Deserialize server's public key
    shared_secret = private_key.exchange(server_public_key)  # Perform ECDH to get shared secret
    print('--- Shared Secret ---')
    print(f'Derived shared secret:       {shared_secret.hex()}\n')

    # 6. Derive the AES-256 key using HKDF
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

    # 7. Send the salt to the server
    s.sendall(salt)  # Send salt

    # 8. Get the message to send
    message = input('Enter message to send: ').encode()  # Get user input and encode to bytes

    # 9. Sign the message with Ed25519
    signature = signing_key.sign(message)  # 64 bytes
    print(f'Generated signature:         {signature.hex()}')

    # 10. Send the Ed25519 public key (32 bytes)
    s.sendall(verify_bytes)
    # 11. Send the signature (64 bytes)
    s.sendall(signature)
    # 12. Send the message length (2 bytes, big endian)
    s.sendall(len(message).to_bytes(2, 'big'))
    # 13. Send the plaintext message
    s.sendall(message)
    print('Message, signature, and public key sent securely! The server should log and verify the message.')
    print('==========================================================\n') 