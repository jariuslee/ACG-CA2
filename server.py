import socket
from crypto_utils import generate_x25519_keypair, derive_shared_secret, hkdf_derive_key, aes_gcm_decrypt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HOST = '127.0.0.1'  # Listen on localhost
PORT = 65432         # Arbitrary non-privileged port

# 1. Generate X25519 keypair for the server
private_key, public_key = generate_x25519_keypair()
# Serialize the public key to bytes for sending
public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f'\n================ SERVER STARTED ================')
    print(f'Server listening on {HOST}:{PORT}\n')
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
        shared_secret = derive_shared_secret(private_key, client_pub_bytes)
        print('--- Shared Secret ---')
        print(f"Derived shared secret:       {shared_secret.hex()}\n")
        # 5. Receive the salt for HKDF from the client
        salt = conn.recv(16)
        print('--- Key Derivation ---')
        print(f"Received salt:               {salt.hex()}")
        # 6. Derive the AES-256 key using HKDF
        key, _ = hkdf_derive_key(shared_secret, salt)
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
            plaintext = aes_gcm_decrypt(key, nonce, ciphertext)
            print('--- Decryption Result ---')
            print('Decrypted message from client:')
            print(f'    "{plaintext.decode()}"\n')
            print('SUCCESS: Secure key exchange and message decryption worked!')
            print('==========================================================\n')
        except Exception as e:
            print('Decryption failed:', e) 