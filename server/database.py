# database.py - Complete MySQL Database Operations with PKI Support
# IT2504 Applied Cryptography Assignment 2

import mysql.connector
from mysql.connector import Error
import hashlib
import secrets

class DatabaseManager:
    """Database manager for secure messaging system with PKI support."""
    
    def __init__(self, host='localhost', database='secure_messaging2', 
                 user='root', password='1qwer$#@!'):
        self.host = host
        self.database = database
        self.user = user
        self.password = password
        self.connection = None
    
    def connect(self):
        """Connect to MySQL database."""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                database=self.database,
                user=self.user,
                password=self.password
            )
            print("Database connected successfully!")
            return True
        except Error as e:
            print(f"Database connection error: {e}")
            return False
    
    def disconnect(self):
        """Close database connection."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("Database connection closed")
    
    def create_user(self, username, password):
        """Create new user with hashed password."""
        try:
            cursor = self.connection.cursor()
            
            # Check if username exists
            cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return False, "Username already exists"
            
            # Hash password with salt
            salt = secrets.token_hex(16)
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            # Insert user
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
                (username, password_hash, salt)
            )
            
            user_id = cursor.lastrowid
            self.connection.commit()
            cursor.close()
            
            print(f"User created: {username}")
            return True, user_id
            
        except Error as e:
            print(f"Error creating user: {e}")
            return False, str(e)
    
    def authenticate_user(self, username, password):
        """Authenticate user login."""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute(
                "SELECT user_id, password_hash, salt FROM users WHERE username = %s",
                (username,)
            )
            result = cursor.fetchone()
            cursor.close()
            
            if not result:
                return False, None
            
            user_id, stored_hash, salt = result
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            if password_hash == stored_hash:
                print(f"User authenticated: {username}")
                return True, user_id
            
            return False, None
            
        except Error as e:
            print(f"Authentication error: {e}")
            return False, None
    
    def store_public_keys(self, user_id, ed25519_key, x25519_key):
        """Store user's public keys."""
        try:
            cursor = self.connection.cursor()
            
            # First, delete any existing keys for this user
            cursor.execute("DELETE FROM public_keys WHERE user_id = %s", (user_id,))
            
            # Insert new keys
            cursor.execute(
                "INSERT INTO public_keys (user_id, ed25519_public_key, x25519_public_key) VALUES (%s, %s, %s)",
                (user_id, ed25519_key, x25519_key)
            )
            
            self.connection.commit()
            cursor.close()
            print(f"Public keys stored for user {user_id}")
            return True
            
        except Error as e:
            print(f"Error storing keys: {e}")
            if self.connection:
                self.connection.rollback()
            return False
    
    def get_public_keys(self, username):
        """Get public keys for a user."""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute("""
                SELECT pk.ed25519_public_key, pk.x25519_public_key 
                FROM public_keys pk
                JOIN users u ON pk.user_id = u.user_id
                WHERE u.username = %s
                ORDER BY pk.key_created_at DESC
                LIMIT 1
            """, (username,))
            
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                return {
                    'ed25519_public_key': result[0],
                    'x25519_public_key': result[1]
                }
            return None
            
        except Error as e:
            print(f"Error getting keys: {e}")
            return None
    
    def get_users(self, exclude_user_id):
        """Get list of users."""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute(
                "SELECT user_id, username FROM users WHERE user_id != %s",
                (exclude_user_id,)
            )
            
            users = []
            for row in cursor.fetchall():
                users.append({'user_id': row[0], 'username': row[1]})
            
            cursor.close()
            return users
            
        except Error as e:
            print(f"Error getting users: {e}")
            return []
    
    def store_message(self, sender_id, recipient_id, encrypted_message, signature, nonce):
        """Store encrypted message."""
        try:
            cursor = self.connection.cursor()
            
            # Validate that both users exist
            cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (sender_id,))
            if not cursor.fetchone():
                print(f"Error: Sender user_id {sender_id} does not exist")
                return False
            
            cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (recipient_id,))
            if not cursor.fetchone():
                print(f"Error: Recipient user_id {recipient_id} does not exist")
                return False
            
            # Store the message
            cursor.execute("""
                INSERT INTO messages (sender_id, recipient_id, encrypted_message, message_signature, nonce) 
                VALUES (%s, %s, %s, %s, %s)
            """, (sender_id, recipient_id, encrypted_message, signature, nonce))
            
            self.connection.commit()
            cursor.close()
            print(f"Message stored: sender={sender_id}, recipient={recipient_id}")
            return True
            
        except Error as e:
            print(f"Error storing message: {e}")
            if self.connection:
                self.connection.rollback()
            return False
    
    def get_messages(self, user_id):
        """Get messages for a user - both sent and received messages."""
        try:
            cursor = self.connection.cursor()
            
            # Get messages where user is EITHER sender OR recipient
            cursor.execute("""
                SELECT m.message_id, m.sender_id, m.recipient_id, m.encrypted_message, 
                       m.message_signature, m.nonce, m.timestamp, 
                       sender.username as sender_username, recipient.username as recipient_username
                FROM messages m
                JOIN users sender ON m.sender_id = sender.user_id
                JOIN users recipient ON m.recipient_id = recipient.user_id
                WHERE m.sender_id = %s OR m.recipient_id = %s
                ORDER BY m.timestamp ASC
            """, (user_id, user_id))
            
            messages = []
            for row in cursor.fetchall():
                messages.append({
                    'message_id': row[0],
                    'sender_id': row[1],
                    'recipient_id': row[2],
                    'encrypted_message': row[3],
                    'signature': row[4],
                    'nonce': row[5],
                    'timestamp': row[6].isoformat() if row[6] else None,
                    'sender_username': row[7],
                    'recipient_username': row[8]
                })
            
            cursor.close()
            print(f"Retrieved {len(messages)} messages for user {user_id} (both sent and received)")
            return messages
            
        except Error as e:
            print(f"Error getting messages: {e}")
            return []
    
    # ==================== PKI CERTIFICATE METHODS ====================
    
    def store_user_certificate(self, user_id, certificate):
        """Store user's certificate."""
        try:
            cursor = self.connection.cursor()
            
            # Check if certificate column exists, if not add it
            cursor.execute("SHOW COLUMNS FROM public_keys LIKE 'certificate'")
            if not cursor.fetchone():
                print("⚠️ Adding certificate column to database...")
                cursor.execute("ALTER TABLE public_keys ADD COLUMN certificate TEXT NULL")
                self.connection.commit()
                print("✅ Certificate column added")
            
            # Update the user's record with certificate
            cursor.execute("""
                UPDATE public_keys 
                SET certificate = %s 
                WHERE user_id = %s
            """, (certificate, user_id))
            
            affected_rows = cursor.rowcount
            self.connection.commit()
            cursor.close()
            
            if affected_rows > 0:
                print(f"✅ Certificate stored for user {user_id}")
                return True
            else:
                print(f"⚠️ No rows updated for user {user_id}")
                return False
                
        except Exception as e:
            print(f"❌ Error storing certificate: {e}")
            if self.connection:
                self.connection.rollback()
            return False

    def get_user_certificate(self, username):
        """Get user's certificate."""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute("""
                SELECT pk.certificate
                FROM public_keys pk
                JOIN users u ON pk.user_id = u.user_id
                WHERE u.username = %s
                ORDER BY pk.key_created_at DESC
                LIMIT 1
            """, (username,))
            
            result = cursor.fetchone()
            cursor.close()
            
            if result and result[0]:
                print(f"✅ Certificate found for {username}")
                return result[0]
            else:
                print(f"⚠️ No certificate found for {username}")
                return None
                
        except Exception as e:
            print(f"❌ Error getting certificate: {e}")
            return None
