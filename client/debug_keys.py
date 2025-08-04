# debug_keys.py - Debug Key Generation Issue
# IT2504 Applied Cryptography Assignment 2

import requests
import json

def test_key_flow():
    """Test the complete key generation and storage flow."""
    
    session = requests.Session()
    
    print("=== DEBUGGING KEY GENERATION ISSUE ===\n")
    
    # Step 1: Register a test user
    print("1. Registering test user...")
    reg_data = {
        'username': 'test_debug_user',
        'password': 'test123456'
    }
    
    reg_response = session.post('http://localhost:5000/api/register', json=reg_data)
    print(f"Registration status: {reg_response.status_code}")
    print(f"Registration response: {reg_response.text}")
    
    if reg_response.status_code != 201:
        print("❌ Registration failed, trying login instead...")
    
    # Step 2: Login
    print("\n2. Logging in...")
    login_data = {
        'username': 'test_debug_user',
        'password': 'test123456'
    }
    
    login_response = session.post('http://localhost:5000/api/login', json=login_data)
    print(f"Login status: {login_response.status_code}")
    print(f"Login response: {login_response.text}")
    
    if login_response.status_code != 200:
        print("❌ Login failed!")
        return
    
    # Step 3: Test key generation locally
    print("\n3. Testing local key generation...")
    try:
        from crypto_utils import ClientCrypto
        crypto = ClientCrypto()
        
        # Generate keys
        keys = crypto.generate_user_keys()
        print("✅ Keys generated successfully!")
        print(f"ED25519 private key length: {len(keys['ed25519']['private'])}")
        print(f"ED25519 public key length: {len(keys['ed25519']['public'])}")
        print(f"X25519 private key length: {len(keys['x25519']['private'])}")
        print(f"X25519 public key length: {len(keys['x25519']['public'])}")
        
        # Step 4: Test key manager
        print("\n4. Testing key manager...")
        from key_manager import ClientKeyManager
        key_manager = ClientKeyManager()
        
        # Generate and get public keys for upload
        public_keys = key_manager.generate_keys_for_user('test_debug_user')
        print("✅ Key manager generated keys!")
        print(f"Public keys for server: {list(public_keys.keys())}")
        print(f"ED25519 public key: {public_keys['ed25519_public_key'][:50]}...")
        print(f"X25519 public key: {public_keys['x25519_public_key'][:50]}...")
        
        # Step 5: Upload keys to server
        print("\n5. Uploading keys to server...")
        upload_data = {
            'ed25519_public_key': public_keys['ed25519_public_key'],
            'x25519_public_key': public_keys['x25519_public_key']
        }
        
        upload_response = session.post('http://localhost:5000/api/keys', json=upload_data)
        print(f"Upload status: {upload_response.status_code}")
        print(f"Upload response: {upload_response.text}")
        
        if upload_response.status_code == 200:
            print("✅ Keys uploaded successfully!")
        else:
            print("❌ Key upload failed!")
            
        # Step 6: Try to retrieve keys
        print("\n6. Retrieving keys from server...")
        get_response = session.get('http://localhost:5000/api/keys/test_debug_user')
        print(f"Get keys status: {get_response.status_code}")
        print(f"Get keys response: {get_response.text}")
        
        if get_response.status_code == 200:
            print("✅ Keys retrieved successfully!")
        else:
            print("❌ Keys not found in database!")
            
    except Exception as e:
        print(f"❌ Error during key testing: {e}")
        import traceback
        traceback.print_exc()

def test_database_connection():
    """Test direct database connection."""
    print("\n=== TESTING DATABASE CONNECTION ===\n")
    
    try:
        from database import DatabaseManager
        db = DatabaseManager(password='1qwer$#@!')
        
        if db.connect():
            print("✅ Database connection successful!")
            
            # Test if tables exist
            cursor = db.connection.cursor()
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()
            print(f"Tables in database: {[table[0] for table in tables]}")
            
            # Check users table
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            print(f"Users in database: {user_count}")
            
            # Check public_keys table
            cursor.execute("SELECT COUNT(*) FROM public_keys")
            key_count = cursor.fetchone()[0]
            print(f"Public keys in database: {key_count}")
            
            cursor.close()
            db.disconnect()
            
        else:
            print("❌ Database connection failed!")
            
    except Exception as e:
        print(f"❌ Database test error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_database_connection()
    print("\n" + "="*50 + "\n")
    test_key_flow()