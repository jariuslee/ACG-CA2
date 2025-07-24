from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate an X25519 key pair (private and public)
def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

# Derive a shared secret using your private key and the peer's public key bytes
def derive_shared_secret(private_key, peer_public_bytes):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

# Use HKDF to derive a 256-bit AES key from the shared secret
def hkdf_derive_key(shared_secret, salt=None, info=b'handshake data'):
    if salt is None:
        salt = os.urandom(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        info=info,
    )
    key = hkdf.derive(shared_secret)
    return key, salt

# Encrypt plaintext using AES-256-GCM
def aes_gcm_encrypt(key, plaintext, associated_data=b''):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext

# Decrypt ciphertext using AES-256-GCM
def aes_gcm_decrypt(key, nonce, ciphertext, associated_data=b''):
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext 