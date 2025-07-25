import socket  # For network communication
import os  # For generating random salt/nonce
from cryptography.hazmat.primitives.asymmetric import x25519  # For X25519 key exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # For key derivation
from cryptography.hazmat.primitives import hashes  # For HKDF hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # For AES-GCM encryption/decryption
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # For public key serialization
from cryptography.hazmat.primitives.asymmetric import ed25519  # For Ed25519 digital signatures
import time  # For timestamp

HOST = '127.0.0.1'  # Server will listen on localhost
PORT = 65432         # Port to listen on

# 1. Generate X25519 keypair for the server (for key exchange)
private_key = x25519.X25519PrivateKey.generate()  # Server's private key
public_key = private_key.public_key()             # Server's public key
public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)  # Serialize public key to bytes

print('\n================ SERVER STARTED ================')
print(f'Server listening on {HOST}:{PORT}\n')

# Create a TCP socket and bind to the address
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))  # Bind to localhost and port
    s.listen(1)           # Listen for a single connection
    conn, addr = s.accept()  # Accept a client connection
    with conn:
        print('---------------- CONNECTION ESTABLISHED ----------------')
        print(f'Connected by: {addr}\n')

        # 2. Receive the client's X25519 public key (32 bytes for X25519)
        client_pub_bytes = conn.recv(32)  # Receive client's public key
        print('--- Key Exchange ---')
        print(f"Received client's public key: {client_pub_bytes.hex()}")

        # 3. Send the server's public key to the client
        conn.sendall(public_bytes)  # Send server's public key
        print(f"Sent server's public key:    {public_bytes.hex()}\n")

        # 4. Derive the shared secret using ECDH
        client_public_key = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)  # Deserialize client's public key
        shared_secret = private_key.exchange(client_public_key)  # Perform ECDH to get shared secret
        print('--- Shared Secret ---')
        print(f"Derived shared secret:       {shared_secret.hex()}\n")

        # 5. Receive the salt for HKDF from the client
        salt = conn.recv(16)  # Receive 16-byte salt
        print('--- Key Derivation ---')
        print(f"Received salt:               {salt.hex()}")

        # 6. Derive the AES-256 key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),  # Use SHA-256
            length=32,                  # 32 bytes = 256 bits
            salt=salt,                  # Use received salt
            info=b'handshake data',     # Context info
        )
        key = hkdf.derive(shared_secret)  # Derive AES key
        print(f"Derived AES-256 key:         {key.hex()}\n")

        # 7. Receive the Ed25519 public key (32 bytes)
        verify_bytes = conn.recv(32)
        print('--- Signature Verification ---')
        print(f"Received Ed25519 public key:  {verify_bytes.hex()}")
        verify_key = ed25519.Ed25519PublicKey.from_public_bytes(verify_bytes)

        # 8. Receive the signature (64 bytes)
        signature = conn.recv(64)
        print(f"Received signature:           {signature.hex()}")

        # 9. Receive the message length (2 bytes, big endian)
        msg_len = int.from_bytes(conn.recv(2), 'big')
        # 10. Receive the plaintext message
        message = conn.recv(msg_len)
        print(f"Received message:             {message.decode()}\n")

        # 11. Verify the signature
        try:
            verify_key.verify(signature, message)
            print('Signature is VALID. Message is authentic and non-repudiable.')
            verification_status = 'VALID'
        except Exception as e:
            print('Signature is INVALID!')
            verification_status = 'INVALID'

        # 12. Log the message, signature, public key, and timestamp to a file
        log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {addr[0]} | {message.decode()} | {signature.hex()} | {verify_bytes.hex()} | {verification_status}\n"
        with open('message_log.txt', 'a') as log:
            log.write(log_entry)
        print('Message logged to message_log.txt')
        print('==========================================================\n') 