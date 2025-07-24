import socket
from crypto_utils import generate_x25519_keypair, derive_shared_secret, hkdf_derive_key, aes_gcm_decrypt

HOST = '127.0.0.1'  # Listen on localhost
PORT = 65432         # Arbitrary non-privileged port

# 1. Generate X25519 keypair
private_key, public_key = generate_x25519_keypair()
public_bytes = public_key.public_bytes()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f'Server listening on {HOST}:{PORT}')
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        # 2. Exchange public keys
        # Receive client's public key
        client_pub_bytes = conn.recv(32)
        conn.sendall(public_bytes)
        # 3. Derive shared secret and AES key
        shared_secret = derive_shared_secret(private_key, client_pub_bytes)
        # Receive salt from client
        salt = conn.recv(16)
        key, _ = hkdf_derive_key(shared_secret, salt)
        # 4. Receive encrypted message
        nonce = conn.recv(12)
        ct_len = int.from_bytes(conn.recv(2), 'big')
        ciphertext = conn.recv(ct_len)
        # 5. Decrypt and print message
        try:
            plaintext = aes_gcm_decrypt(key, nonce, ciphertext)
            print('Decrypted message from client:', plaintext.decode())
        except Exception as e:
            print('Decryption failed:', e) 