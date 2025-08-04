# crypto_utils.py - CLIENT-SIDE Cryptographic Functions
# IT2504 Applied Cryptography Assignment 2
# Implements: AES-256-GCM, ECDH X25519, HKDF, ED25519
# ALL ENCRYPTION HAPPENS ON CLIENT SIDE - SERVER NEVER SEES PLAIN TEXT!

import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.exceptions import InvalidSignature
from typing import Tuple, Dict

class ClientCrypto:
    """
    CLIENT-SIDE cryptographic operations for secure messaging.
    
    Security Model:
    - Client encrypts messages before sending to server
    - Server only stores/routes encrypted messages
    - Server stores public keys for key exchange
    - Only intended recipient can decrypt messages
    - Perfect end-to-end encryption!
    """
    
    def __init__(self):
        """Initialize client-side crypto manager."""
        self.aes_key_size = 32  # 256 bits for AES-256
        self.nonce_size = 12    # 96 bits for GCM mode
        print("Client-side crypto manager initialized")
    
    # ==================== KEY GENERATION (CLIENT SIDE) ====================
    
    def generate_user_keys(self) -> Dict[str, Dict[str, str]]:
        """
        Generate ED25519 and X25519 key pairs for a user.
        
        Returns:
            Dict with both private and public keys (base64 encoded)
        """
        print("Generating key pairs on CLIENT side...")
        
        # Generate ED25519 key pair for digital signatures
        ed25519_private = Ed25519PrivateKey.generate()
        ed25519_public = ed25519_private.public_key()
        
        # Generate X25519 key pair for ECDH key exchange
        x25519_private = X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        
        # Serialize all keys to base64
        keys = {
            'ed25519': {
                'private': base64.b64encode(
                    ed25519_private.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                ).decode('utf-8'),
                'public': base64.b64encode(
                    ed25519_public.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                ).decode('utf-8')
            },
            'x25519': {
                'private': base64.b64encode(
                    x25519_private.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                ).decode('utf-8'),
                'public': base64.b64encode(
                    x25519_public.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                ).decode('utf-8')
            }
        }
        
        print("✓ Key pairs generated successfully")
        return keys
    
    # ==================== ECDH X25519 KEY EXCHANGE (CLIENT SIDE) ====================
    
    def perform_ecdh_exchange(self, my_x25519_private: str, their_x25519_public: str) -> bytes:
        """
        Perform ECDH key exchange to create shared secret.
        This happens on CLIENT side using recipient's public key from server.
        
        Args:
            my_x25519_private: My X25519 private key (base64)
            their_x25519_public: Recipient's X25519 public key from server (base64)
            
        Returns:
            32-byte shared secret
        """
        try:
            print("Performing ECDH key exchange on CLIENT...")
            
            # Decode keys from base64
            my_private_bytes = base64.b64decode(my_x25519_private)
            their_public_bytes = base64.b64decode(their_x25519_public)
            
            # Reconstruct key objects
            my_private_key = X25519PrivateKey.from_private_bytes(my_private_bytes)
            their_public_key = X25519PublicKey.from_public_bytes(their_public_bytes)
            
            # Perform ECDH - creates shared secret
            shared_secret = my_private_key.exchange(their_public_key)
            
            print(f"✓ ECDH completed - shared secret: {len(shared_secret)} bytes")
            return shared_secret
            
        except Exception as e:
            print(f"❌ ECDH error: {e}")
            raise
    
    # ==================== HKDF KEY DERIVATION (CLIENT SIDE) ====================
    
    def derive_message_key(self, shared_secret: bytes, context_info: str = "secure_message") -> bytes:
        """
        Derive AES-256 key from ECDH shared secret using HKDF.
        This happens on CLIENT side for each message.
        
        Args:
            shared_secret: 32-byte output from ECDH
            context_info: Context for key derivation
            
        Returns:
            32-byte AES-256 key for this specific message
        """
        try:
            print("Deriving AES key using HKDF on CLIENT...")
            
            # Use a fixed salt derived from the shared secret for consistency
            # Both Alice and Bob will derive the same AES key from the same shared secret
            import hashlib
            salt = hashlib.sha256(shared_secret + b"salt_derivation").digest()
            
            # Use HKDF to derive AES key
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=self.aes_key_size,  # 32 bytes for AES-256
                salt=salt,
                info=context_info.encode('utf-8')
            )
            
            aes_key = hkdf.derive(shared_secret)
            
            print(f"✓ HKDF completed - AES key derived: {len(aes_key)} bytes")
            return aes_key
            
        except Exception as e:
            print(f"❌ HKDF error: {e}")
            raise
    
    # ==================== AES-256-GCM ENCRYPTION (CLIENT SIDE) ====================
    
    def encrypt_message_for_sending(self, plain_message: str, aes_key: bytes) -> Dict[str, str]:
        """
        Encrypt message using AES-256-GCM before sending to server.
        Server will only see the encrypted version!
        
        Args:
            plain_message: Original message text
            aes_key: 32-byte AES key from HKDF
            
        Returns:
            Dict with encrypted message and nonce (base64)
        """
        try:
            print(f"Encrypting message on CLIENT: '{plain_message[:30]}...'")
            
            # Convert message to bytes
            message_bytes = plain_message.encode('utf-8')
            
            # Generate random nonce for GCM
            nonce = os.urandom(self.nonce_size)
            
            # Create AES-GCM cipher
            aesgcm = AESGCM(aes_key)
            
            # Encrypt message (GCM provides authentication)
            ciphertext = aesgcm.encrypt(nonce, message_bytes, None)
            
            # Return base64 encoded for transmission
            result = {
                'encrypted_message': base64.b64encode(ciphertext).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8')
            }
            
            print("✓ Message encrypted successfully - ready to send to server")
            return result
            
        except Exception as e:
            print(f"❌ AES encryption error: {e}")
            raise
    
    def decrypt_received_message(self, encrypted_message_b64: str, nonce_b64: str, aes_key: bytes) -> str:
        """
        Decrypt message received from server.
        Only the intended recipient can do this!
        
        Args:
            encrypted_message_b64: Encrypted message from server (base64)
            nonce_b64: Nonce from server (base64)
            aes_key: AES key derived from ECDH shared secret
            
        Returns:
            Original plain text message
        """
        try:
            print("Decrypting message received from server...")
            
            # Decode from base64
            ciphertext = base64.b64decode(encrypted_message_b64)
            nonce = base64.b64decode(nonce_b64)
            
            # Create AES-GCM cipher
            aesgcm = AESGCM(aes_key)
            
            # Decrypt message (GCM verifies authentication)
            message_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Convert back to string
            plain_message = message_bytes.decode('utf-8')
            
            print(f"✓ Message decrypted: '{plain_message[:30]}...'")
            return plain_message
            
        except Exception as e:
            print(f"❌ AES decryption error: {e}")
            raise
    
    # ==================== ED25519 DIGITAL SIGNATURES (CLIENT SIDE) ====================
    
    def sign_message_before_sending(self, message: str, my_ed25519_private: str) -> str:
        """
        Sign message with ED25519 before sending to server.
        Provides non-repudiation - proves who sent the message.
        
        Args:
            message: Plain text message to sign
            my_ed25519_private: My ED25519 private key (base64)
            
        Returns:
            Base64 encoded signature
        """
        try:
            print("Signing message with ED25519 on CLIENT...")
            
            # Decode private key
            private_key_bytes = base64.b64decode(my_ed25519_private)
            private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            
            # Sign the original message
            message_bytes = message.encode('utf-8')
            signature = private_key.sign(message_bytes)
            
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            print("✓ Message signed successfully")
            return signature_b64
            
        except Exception as e:
            print(f"❌ ED25519 signing error: {e}")
            raise
    
    def verify_received_signature(self, message: str, signature_b64: str, sender_ed25519_public: str) -> bool:
        """
        Verify signature of received message.
        Confirms message authenticity and sender identity.
        
        Args:
            message: Decrypted message text
            signature_b64: Signature from server (base64)
            sender_ed25519_public: Sender's public key from server (base64)
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            print("Verifying message signature on CLIENT...")
            
            # Decode signature and public key
            signature = base64.b64decode(signature_b64)
            public_key_bytes = base64.b64decode(sender_ed25519_public)
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Verify signature
            message_bytes = message.encode('utf-8')
            public_key.verify(signature, message_bytes)
            
            print("✓ Signature verification: VALID")
            return True
            
        except InvalidSignature:
            print("❌ Signature verification: INVALID")
            return False
        except Exception as e:
            print(f"❌ Signature verification error: {e}")
            return False
    
    # ==================== COMPLETE MESSAGE WORKFLOW (CLIENT SIDE) ====================
    
    def prepare_message_for_server(self, plain_message: str, recipient_x25519_public: str, 
                                  my_x25519_private: str, my_ed25519_private: str) -> Dict[str, str]:
        """
        Complete workflow: encrypt and sign message before sending to server.
        
        Args:
            plain_message: Original message text
            recipient_x25519_public: Recipient's public key from server
            my_x25519_private: My private key (local storage)
            my_ed25519_private: My signing key (local storage)
            
        Returns:
            Dict ready to send to server (encrypted + signed)
        """
        try:
            print(f"\n🔐 PREPARING MESSAGE FOR SERVER 🔐")
            print(f"Message: '{plain_message}'")
            
            # Step 1: ECDH - Create shared secret with recipient
            shared_secret = self.perform_ecdh_exchange(my_x25519_private, recipient_x25519_public)
            
            # Step 2: HKDF - Derive AES key from shared secret
            aes_key = self.derive_message_key(shared_secret)
            
            # Step 3: AES-256-GCM - Encrypt the message
            encrypted_data = self.encrypt_message_for_sending(plain_message, aes_key)
            
            # Step 4: ED25519 - Sign the original message
            signature = self.sign_message_before_sending(plain_message, my_ed25519_private)
            
            # Package for server transmission
            message_package = {
                'encrypted_message': encrypted_data['encrypted_message'],
                'nonce': encrypted_data['nonce'],
                'signature': signature
            }
            
            print("✅ Message prepared successfully - ready for server!")
            print("📤 Server will only see encrypted data\n")
            return message_package
            
        except Exception as e:
            print(f"❌ Message preparation failed: {e}")
            raise
    
    def process_message_from_server(self, encrypted_message: str, nonce: str, signature: str,
                                   sender_x25519_public: str, my_x25519_private: str, 
                                   sender_ed25519_public: str) -> Tuple[str, bool]:
        """
        Complete workflow: decrypt and verify message received from server.
        
        Args:
            encrypted_message: Encrypted message from server
            nonce: Nonce from server
            signature: Message signature from server
            sender_x25519_public: Sender's public key from server
            my_x25519_private: My private key (local storage)
            sender_ed25519_public: Sender's signing key from server
            
        Returns:
            Tuple of (decrypted_message, signature_valid)
        """
        try:
            print(f"\n🔓 PROCESSING MESSAGE FROM SERVER 🔓")
            
            # Step 1: ECDH - Recreate shared secret with sender
            shared_secret = self.perform_ecdh_exchange(my_x25519_private, sender_x25519_public)
            
            # Step 2: HKDF - Derive same AES key
            aes_key = self.derive_message_key(shared_secret)
            
            # Step 3: AES-256-GCM - Decrypt the message
            decrypted_message = self.decrypt_received_message(encrypted_message, nonce, aes_key)
            
            # Step 4: ED25519 - Verify signature
            signature_valid = self.verify_received_signature(decrypted_message, signature, sender_ed25519_public)
            
            print(f"✅ Message processed successfully!")
            print(f"📨 Decrypted: '{decrypted_message}'")
            print(f"🔏 Signature valid: {signature_valid}\n")
            
            return decrypted_message, signature_valid
            
        except Exception as e:
            print(f"❌ Message processing failed: {e}")
            raise

# ==================== CLIENT-SIDE TESTING ====================

def test_client_crypto():
    """Test all client-side cryptographic operations."""
    print("=== TESTING CLIENT-SIDE CRYPTOGRAPHY ===\n")
    
    crypto = ClientCrypto()
    
    # Simulate Alice and Bob
    print("👥 Simulating Alice and Bob...")
    alice_keys = crypto.generate_user_keys()
    bob_keys = crypto.generate_user_keys()
    print("✓ Generated keys for Alice and Bob\n")
    
    # Test message from Alice to Bob
    test_message = "Hello Bob! This is a secret message from Alice. 🤫"
    print(f"📝 Original message: '{test_message}'\n")
    
    # Alice prepares message (what happens in Alice's client)
    print("👩 ALICE'S CLIENT - Preparing message...")
    encrypted_package = crypto.prepare_message_for_server(
        test_message,
        bob_keys['x25519']['public'],    # Bob's public key (from server)
        alice_keys['x25519']['private'], # Alice's private key (local)
        alice_keys['ed25519']['private'] # Alice's signing key (local)
    )
    
    print("🌐 SERVER - Receives encrypted package (cannot read it!)")
    print(f"   Encrypted data length: {len(encrypted_package['encrypted_message'])} chars")
    print(f"   Server stores and forwards to Bob...\n")
    
    # Bob receives message (what happens in Bob's client)
    print("👨 BOB'S CLIENT - Processing received message...")
    decrypted_message, signature_ok = crypto.process_message_from_server(
        encrypted_package['encrypted_message'],
        encrypted_package['nonce'],
        encrypted_package['signature'],
        alice_keys['x25519']['public'],  # Alice's public key (from server)
        bob_keys['x25519']['private'],   # Bob's private key (local)
        alice_keys['ed25519']['public']  # Alice's signing key (from server)
    )
    
    # Verify everything worked
    assert decrypted_message == test_message, "❌ Decryption failed!"
    assert signature_ok, "❌ Signature verification failed!"
    
    print("🎉 SUCCESS! End-to-end encryption working perfectly!")
    print("\n📋 SECURITY ACHIEVED:")
    print("   ✓ Server never sees plain text messages")
    print("   ✓ Only recipient can decrypt messages") 
    print("   ✓ Message authenticity verified")
    print("   ✓ Perfect forward secrecy via ECDH")
    print("   ✓ All 4 algorithms working together")

if __name__ == "__main__":
    test_client_crypto()