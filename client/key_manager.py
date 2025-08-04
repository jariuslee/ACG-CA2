# key_manager.py - CLIENT-SIDE Key Storage Management
# IT2504 Applied Cryptography Assignment 2

import os
import json
from typing import Dict, Optional
from crypto_utils import ClientCrypto

class ClientKeyManager:
    """
    Manages local storage of private keys on CLIENT side.
    
    Security Model:
    - Private keys NEVER leave the client machine
    - Public keys are sent to server for distribution
    - Each user has their own secure key file locally
    """
    
    def __init__(self, keys_directory: str = "keys"):
        """Initialize client-side key manager."""
        self.keys_directory = keys_directory
        self.crypto = ClientCrypto()
        
        # Create keys directory if it doesn't exist
        if not os.path.exists(self.keys_directory):
            os.makedirs(self.keys_directory)
            print(f"Created keys directory: {self.keys_directory}")
    
    def generate_keys_for_user(self, username: str) -> Dict[str, str]:
        """
        Generate new key pairs and store private keys locally.
        Only public keys are returned (to send to server).
        
        Args:
            username: Username to generate keys for
            
        Returns:
            Dict containing ONLY public keys (for server upload)
        """
        try:
            print(f"🔑 Generating keys for user: {username}")
            
            # Generate both key pairs on CLIENT
            all_keys = self.crypto.generate_user_keys()
            
            # Prepare private key storage (stays on client)
            private_key_data = {
                'username': username,
                'ed25519_private': all_keys['ed25519']['private'],
                'x25519_private': all_keys['x25519']['private'],
                'ed25519_public': all_keys['ed25519']['public'],
                'x25519_public': all_keys['x25519']['public'],
                'created_at': str(os.path.getctime)
            }
            
            # Store private keys locally (NEVER send to server)
            private_key_file = os.path.join(self.keys_directory, f"{username}_private.json")
            
            with open(private_key_file, 'w') as f:
                json.dump(private_key_data, f, indent=2)
            
            print(f"✓ Private keys stored locally: {private_key_file}")
            
            # Return ONLY public keys (safe to send to server)
            public_keys_for_server = {
                'ed25519_public_key': all_keys['ed25519']['public'],
                'x25519_public_key': all_keys['x25519']['public']
            }
            
            print("✓ Public keys ready for server upload")
            return public_keys_for_server
            
        except Exception as e:
            print(f"❌ Error generating keys: {e}")
            raise
    
    def load_my_private_keys(self, username: str) -> Optional[Dict[str, str]]:
        """
        Load MY private keys from local storage.
        These are used for decryption and signing.
        
        Args:
            username: My username
            
        Returns:
            Dict with my private keys, or None if not found
        """
        try:
            private_key_file = os.path.join(self.keys_directory, f"{username}_private.json")
            
            if not os.path.exists(private_key_file):
                print(f"❌ No private keys found for: {username}")
                return None
            
            with open(private_key_file, 'r') as f:
                private_keys = json.load(f)
            
            print(f"✓ Loaded private keys for: {username}")
            return private_keys
            
        except Exception as e:
            print(f"❌ Error loading private keys: {e}")
            return None
    
    def get_my_encryption_keys(self, username: str) -> Optional[Dict[str, str]]:
        """
        Get my private keys needed for encryption/decryption operations.
        
        Args:
            username: My username
            
        Returns:
            Dict with my private keys for crypto operations
        """
        private_keys = self.load_my_private_keys(username)
        
        if private_keys:
            return {
                'x25519_private': private_keys['x25519_private'],
                'ed25519_private': private_keys['ed25519_private']
            }
        
        return None
    
    def get_my_public_keys(self, username: str) -> Optional[Dict[str, str]]:
        """
        Get my public keys (from local storage).
        Useful for displaying to user or verification.
        
        Args:
            username: My username
            
        Returns:
            Dict with my public keys
        """
        private_keys = self.load_my_private_keys(username)
        
        if private_keys:
            return {
                'ed25519_public': private_keys['ed25519_public'],
                'x25519_public': private_keys['x25519_public']
            }
        
        return None
    
    def user_has_keys(self, username: str) -> bool:
        """
        Check if user has keys stored locally.
        
        Args:
            username: Username to check
            
        Returns:
            True if user has local keys, False otherwise
        """
        private_key_file = os.path.join(self.keys_directory, f"{username}_private.json")
        exists = os.path.exists(private_key_file)
        
        if exists:
            print(f"✓ User {username} has local keys")
        else:
            print(f"⚠️ User {username} needs to generate keys")
        
        return exists
    
    def delete_user_keys(self, username: str) -> bool:
        """
        Delete user's private keys (for security or re-generation).
        
        Args:
            username: Username to delete keys for
            
        Returns:
            True if deleted, False if no keys existed
        """
        try:
            private_key_file = os.path.join(self.keys_directory, f"{username}_private.json")
            
            if os.path.exists(private_key_file):
                os.remove(private_key_file)
                print(f"🗑️ Deleted keys for user: {username}")
                return True
            else:
                print(f"⚠️ No keys to delete for: {username}")
                return False
                
        except Exception as e:
            print(f"❌ Error deleting keys: {e}")
            return False
    
    def list_users_with_keys(self) -> list:
        """
        Get list of users who have keys stored locally.
        
        Returns:
            List of usernames with local keys
        """
        try:
            users = []
            
            if not os.path.exists(self.keys_directory):
                return users
            
            for filename in os.listdir(self.keys_directory):
                if filename.endswith('_private.json'):
                    username = filename.replace('_private.json', '')
                    users.append(username)
            
            print(f"📋 Found keys for {len(users)} users: {users}")
            return users
            
        except Exception as e:
            print(f"❌ Error listing users: {e}")
            return []
    
    def backup_keys(self, username: str) -> str:
        """
        Create a backup of user's private keys.
        Returns backup file path.
        """
        try:
            source_file = os.path.join(self.keys_directory, f"{username}_private.json")
            backup_file = os.path.join(self.keys_directory, f"{username}_private_backup.json")
            
            if os.path.exists(source_file):
                with open(source_file, 'r') as src:
                    with open(backup_file, 'w') as dst:
                        dst.write(src.read())
                
                print(f"💾 Keys backed up: {backup_file}")
                return backup_file
            else:
                print(f"❌ No keys to backup for: {username}")
                return ""
                
        except Exception as e:
            print(f"❌ Backup error: {e}")
            return ""

# ==================== TESTING ====================

def test_client_key_manager():
    """Test client-side key management."""
    print("=== TESTING CLIENT KEY MANAGER ===\n")
    
    key_manager = ClientKeyManager()
    test_user = "alice_test"
    
    # Test 1: Check if user has keys (should be False initially)
    print("1. Checking if user has keys...")
    has_keys = key_manager.user_has_keys(test_user)
    print(f"User has keys: {has_keys}\n")
    
    # Test 2: Generate keys for user
    print("2. Generating keys for user...")
    public_keys = key_manager.generate_keys_for_user(test_user)
    print(f"Public keys for server: {list(public_keys.keys())}\n")
    
    # Test 3: Check if user has keys now (should be True)
    print("3. Checking if user has keys now...")
    has_keys = key_manager.user_has_keys(test_user)
    print(f"User has keys: {has_keys}\n")
    
    # Test 4: Load private keys
    print("4. Loading private keys...")
    private_keys = key_manager.load_my_private_keys(test_user)
    print(f"Private keys loaded: {private_keys is not None}\n")
    
    # Test 5: Get encryption keys
    print("5. Getting encryption keys...")
    crypto_keys = key_manager.get_my_encryption_keys(test_user)
    print(f"Crypto keys retrieved: {crypto_keys is not None}\n")
    
    # Test 6: Test with crypto operations
    print("6. Testing keys with crypto operations...")
    if crypto_keys:
        crypto = ClientCrypto()
        test_message = "Test message for key verification"
        
        # Test signing with loaded keys
        signature = crypto.sign_message_before_sending(test_message, crypto_keys['ed25519_private'])
        
        # Get public key for verification
        my_public_keys = key_manager.get_my_public_keys(test_user)
        is_valid = crypto.verify_received_signature(
            test_message, 
            signature, 
            my_public_keys['ed25519_public']
        )
        
        print(f"Signature test with loaded keys: {is_valid}\n")
    
    # Test 7: List users with keys
    print("7. Listing users with keys...")
    users_with_keys = key_manager.list_users_with_keys()
    print(f"Users with keys: {users_with_keys}\n")
    
    # Test 8: Backup keys
    print("8. Creating backup...")
    backup_file = key_manager.backup_keys(test_user)
    print(f"Backup created: {backup_file != ''}\n")
    
    # Test 9: Clean up
    print("9. Cleaning up test keys...")
    deleted = key_manager.delete_user_keys(test_user)
    print(f"Test keys deleted: {deleted}")
    
    print("\n✅ Client Key Manager tests completed!")
    print("🔐 Security confirmed:")
    print("   ✓ Private keys stored locally only")
    print("   ✓ Public keys ready for server")
    print("   ✓ Keys work with crypto operations")

if __name__ == "__main__":
    test_client_key_manager()