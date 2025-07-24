import socket
from crypto_utils import generate_x25519_keypair, derive_shared_secret, hkdf_derive_key, aes_gcm_encrypt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HOST = '127.0.0.1'  # Server address
PORT = 65432         # Server port

# 1. Generate X25519 keypair for the client
private_key, public_key = generate_x25519_keypair()
# Serialize the public key to bytes for sending
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
    print('--- Shared Secret ---')
    shared_secret = derive_shared_secret(private_key, server_pub_bytes)
    print(f'Derived shared secret:       {shared_secret.hex()}\n')
    # 5. Derive the AES-256 key using HKDF
    print('--- Key Derivation ---')
    key, salt = hkdf_derive_key(shared_secret)
    print(f'Generated salt:              {salt.hex()}')
    print(f'Derived AES-256 key:         {key.hex()}\n')
    # 6. Send the salt to the server
    s.sendall(salt)
    # 7. Get the message to send
    message = input('Enter message to send: ').encode()
    # 8. Encrypt the message using AES-256-GCM
    print('\n--- Message Encryption ---')
    nonce, ciphertext = aes_gcm_encrypt(key, message)
    print(f'Generated nonce:             {nonce.hex()}')
    print(f'Ciphertext:                  {ciphertext.hex()}\n')
    # 9. Send the nonce, ciphertext length, and ciphertext to the server
    s.sendall(nonce)
    s.sendall(len(ciphertext).to_bytes(2, 'big'))
    s.sendall(ciphertext)
    print('Message sent securely! The server should print the decrypted message.')
    print('==========================================================\n') 