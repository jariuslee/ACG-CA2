import socket
from crypto_utils import generate_x25519_keypair, derive_shared_secret, hkdf_derive_key, aes_gcm_encrypt

HOST = '127.0.0.1'  # Server address
PORT = 65432         # Server port

# 1. Generate X25519 keypair
private_key, public_key = generate_x25519_keypair()
public_bytes = public_key.public_bytes()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    # 2. Exchange public keys
    s.sendall(public_bytes)
    server_pub_bytes = s.recv(32)
    # 3. Derive shared secret and AES key
    shared_secret = derive_shared_secret(private_key, server_pub_bytes)
    key, salt = hkdf_derive_key(shared_secret)
    s.sendall(salt)
    # 4. Encrypt message
    message = input('Enter message to send: ').encode()
    nonce, ciphertext = aes_gcm_encrypt(key, message)
    # 5. Send encrypted message
    s.sendall(nonce)
    s.sendall(len(ciphertext).to_bytes(2, 'big'))
    s.sendall(ciphertext)
    print('Message sent securely.') 