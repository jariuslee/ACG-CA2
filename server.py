import socket  # For network communication
import os  # For generating random salt/nonce
from cryptography.hazmat.primitives.asymmetric import x25519  # For X25519 key exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # For key derivation
from cryptography.hazmat.primitives import hashes  # For HKDF hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # For AES-GCM encryption/decryption
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # For public key serialization

HOST = '127.0.0.1'  # Server will listen on localhost
PORT = 65432         # Port to listen on

# 1. Generate X25519 keypair for the server
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

        # 2. Receive the client's public key (32 bytes for X25519)
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

        # 7. Receive the nonce (12 bytes for AES-GCM)
        nonce = conn.recv(12)  # Receive 12-byte nonce
        print('--- Message Reception ---')
        print(f"Received nonce:              {nonce.hex()}")

        # 8. Receive the ciphertext length (2 bytes, big endian)
        ct_len = int.from_bytes(conn.recv(2), 'big')  # Receive ciphertext length

        # 9. Receive the ciphertext
        ciphertext = conn.recv(ct_len)  # Receive ciphertext
        print(f"Received ciphertext:         {ciphertext.hex()}\n")

        # 10. Decrypt the message
        try:
            aesgcm = AESGCM(key)  # Create AESGCM object with derived key
            plaintext = aesgcm.decrypt(nonce, ciphertext, b'')  # Decrypt ciphertext
            print('--- Decryption Result ---')
            print('Decrypted message from client:')
            print(f'    "{plaintext.decode()}"\n')
            print('SUCCESS: Secure key exchange and message decryption worked!')
            print('==========================================================\n')
        except Exception as e:
            print('Decryption failed:', e) 