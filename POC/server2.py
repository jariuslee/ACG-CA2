#!/usr/bin/env python3
"""
Phase 1: Basic Server Foundation
IT2504 Applied Cryptography Assignment 2

Goal: Core infrastructure with MySQL and basic multi-client support
- Database connection and user management
- Basic server socket architecture
- User registration/login (WITHOUT crypto for now)
- Username uniqueness validation
- Multi-client connection handling

Author: Jarius Lee Jie Ren
"""

import socket
import threading
import mysql.connector
import hashlib
import json
import time
import logging
from datetime import datetime

# Configuration
CONFIG = {
    'HOST': '127.0.0.1',
    'PORT': 65432,
    'DB_HOST': 'localhost',
    'DB_USER': 'root',
    'DB_PASSWORD': '1qwer$#@',  
    'DB_NAME': 'acg_ca2',
    'MAX_CLIENTS': 5
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Simple database manager for Phase 1"""
    
    def __init__(self):
        self.connection = None
        self.connect_to_database()
        self.setup_basic_tables()
    
    def connect_to_database(self):
        """Connect to MySQL and create database if needed"""
        try:
            # First try to connect to the specific database
            self.connection = mysql.connector.connect(
                host=CONFIG['DB_HOST'],
                user=CONFIG['DB_USER'],
                password=CONFIG['DB_PASSWORD'],
                database=CONFIG['DB_NAME']
            )
            logger.info(f"✅ Connected to database '{CONFIG['DB_NAME']}'")
            
        except mysql.connector.Error as err:
            if err.errno == mysql.connector.errorcode.ER_BAD_DB_ERROR:
                logger.info("Database doesn't exist. Creating it...")
                self.create_database()
            else:
                logger.error(f"❌ Database error: {err}")
                raise
    
    def create_database(self):
        """Create the database and connect to it"""
        try:
            # Connect without specifying database
            temp_conn = mysql.connector.connect(
                host=CONFIG['DB_HOST'],
                user=CONFIG['DB_USER'],
                password=CONFIG['DB_PASSWORD']
            )
            cursor = temp_conn.cursor()
            
            # Create database
            cursor.execute(f"CREATE DATABASE {CONFIG['DB_NAME']}")
            cursor.close()
            temp_conn.close()
            
            logger.info(f"✅ Database '{CONFIG['DB_NAME']}' created successfully")
            
            # Now connect to the new database
            self.connection = mysql.connector.connect(
                host=CONFIG['DB_HOST'],
                user=CONFIG['DB_USER'],
                password=CONFIG['DB_PASSWORD'],
                database=CONFIG['DB_NAME']
            )
            
        except mysql.connector.Error as err:
            logger.error(f"❌ Failed to create database: {err}")
            raise
    
    def setup_basic_tables(self):
        """Create basic tables for Phase 1"""
        cursor = self.connection.cursor()
        
        try:
            # Simple users table for Phase 1
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(64) NOT NULL,
                    salt VARCHAR(32) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL,
                    is_online BOOLEAN DEFAULT FALSE
                )
            """)
            
            # Simple sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    session_token VARCHAR(64) UNIQUE NOT NULL,
                    client_ip VARCHAR(45) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            # Basic connection log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connection_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NULL,
                    action VARCHAR(50) NOT NULL,
                    ip_address VARCHAR(45) NOT NULL,
                    success BOOLEAN NOT NULL,
                    message TEXT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                )
            """)
            
            self.connection.commit()
            logger.info("✅ Database tables created successfully")
            
        except mysql.connector.Error as err:
            logger.error(f"❌ Error creating tables: {err}")
            raise
        finally:
            cursor.close()
    
    def register_user(self, username, password):
        """Register a new user (simple hash for Phase 1)"""
        cursor = self.connection.cursor()
        
        try:
            # Generate salt and hash password
            import os
            salt = os.urandom(16).hex()
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            # Insert user
            cursor.execute("""
                INSERT INTO users (username, password_hash, salt)
                VALUES (%s, %s, %s)
            """, (username, password_hash, salt))
            
            user_id = cursor.lastrowid
            self.connection.commit()
            
            logger.info(f"✅ User '{username}' registered with ID {user_id}")
            return user_id
            
        except mysql.connector.IntegrityError:
            logger.warning(f"❌ Username '{username}' already exists")
            return None
        except Exception as e:
            logger.error(f"❌ Registration error: {e}")
            return None
        finally:
            cursor.close()
    
    def authenticate_user(self, username, password):
        """Authenticate user (simple for Phase 1)"""
        cursor = self.connection.cursor()
        
        try:
            # Get user data
            cursor.execute("""
                SELECT id, password_hash, salt FROM users WHERE username = %s
            """, (username,))
            
            result = cursor.fetchone()
            if not result:
                return None
            
            user_id, stored_hash, salt = result
            
            # Verify password
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            if password_hash != stored_hash:
                return None
            
            # Update last login and online status
            cursor.execute("""
                UPDATE users SET last_login = NOW(), is_online = TRUE WHERE id = %s
            """, (user_id,))
            self.connection.commit()
            
            logger.info(f"✅ User '{username}' authenticated successfully")
            return {
                'id': user_id,
                'username': username
            }
            
        except Exception as e:
            logger.error(f"❌ Authentication error: {e}")
            return None
        finally:
            cursor.close()
    
    def create_session(self, user_id, session_token, client_ip):
        """Create a user session"""
        cursor = self.connection.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO sessions (user_id, session_token, client_ip)
                VALUES (%s, %s, %s)
            """, (user_id, session_token, client_ip))
            
            session_id = cursor.lastrowid
            self.connection.commit()
            
            logger.info(f"✅ Session created for user {user_id}")
            return session_id
            
        except Exception as e:
            logger.error(f"❌ Session creation error: {e}")
            return None
        finally:
            cursor.close()
    
    def log_connection_event(self, user_id, action, ip_address, success, message=None):
        """Log connection events"""
        cursor = self.connection.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO connection_log (user_id, action, ip_address, success, message)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, action, ip_address, success, message))
            self.connection.commit()
            
        except Exception as e:
            logger.error(f"❌ Logging error: {e}")
        finally:
            cursor.close()
    
    def get_online_users(self):
        """Get list of online users"""
        cursor = self.connection.cursor()
        
        try:
            cursor.execute("SELECT username FROM users WHERE is_online = TRUE")
            return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"❌ Error getting online users: {e}")
            return []
        finally:
            cursor.close()
    
    def set_user_offline(self, user_id):
        """Mark user as offline"""
        cursor = self.connection.cursor()
        
        try:
            cursor.execute("UPDATE users SET is_online = FALSE WHERE id = %s", (user_id,))
            self.connection.commit()
        except Exception as e:
            logger.error(f"❌ Error setting user offline: {e}")
        finally:
            cursor.close()

class BasicMessagingServer:
    """Basic server for Phase 1 - no crypto yet"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.clients = {}  # session_token -> client_info
        self.server_socket = None
        
    def start_server(self):
        """Start the basic server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((CONFIG['HOST'], CONFIG['PORT']))
            self.server_socket.listen(CONFIG['MAX_CLIENTS'])
            
            print("\n" + "="*60)
            print("🚀 PHASE 1: BASIC MESSAGING SERVER")
            print("="*60)
            print(f"📍 Server Address: {CONFIG['HOST']}:{CONFIG['PORT']}")
            print(f"🗄️  Database: {CONFIG['DB_NAME']}")
            print(f"👥 Max Clients: {CONFIG['MAX_CLIENTS']}")
            print(f"📊 Features: Registration, Login, Multi-client")
            print("="*60)
            
            logger.info(f"🚀 Server started on {CONFIG['HOST']}:{CONFIG['PORT']}")
            
            while True:
                try:
                    client_socket, address = self.server_socket.accept()
                    logger.info(f"🔗 New connection from {address}")
                    
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    logger.error(f"❌ Error accepting client: {e}")
                    
        except Exception as e:
            logger.error(f"❌ Server startup error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        client_ip = address[0]
        user_data = None
        session_token = None
        
        try:
            logger.info(f"👋 Handling client from {client_ip}")
            
            while True:
                # Receive data from client
                data = client_socket.recv(1024)
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode())
                    response = self.process_message(message, client_ip, user_data)
                    
                    # Send response
                    client_socket.send(json.dumps(response).encode())
                    
                    # Update user_data and session_token if login was successful
                    if message.get('action') == 'login' and response.get('success'):
                        user_data = response['user_data']
                        session_token = response['session_token']
                        
                        # Store client info
                        self.clients[session_token] = {
                            'socket': client_socket,
                            'user_data': user_data,
                            'address': address
                        }
                    
                except json.JSONDecodeError:
                    error_response = {'success': False, 'message': 'Invalid JSON'}
                    client_socket.send(json.dumps(error_response).encode())
                except Exception as e:
                    logger.error(f"❌ Error processing message: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"❌ Client handling error: {e}")
        finally:
            # Cleanup
            if session_token and session_token in self.clients:
                del self.clients[session_token]
            if user_data:
                self.db.set_user_offline(user_data['id'])
                logger.info(f"👋 User '{user_data['username']}' disconnected")
            
            client_socket.close()
            logger.info(f"🔌 Client {client_ip} disconnected")
    
    def process_message(self, message, client_ip, user_data):
        """Process messages from clients"""
        action = message.get('action')
        
        if action == 'register':
            return self.handle_registration(message, client_ip)
        elif action == 'login':
            return self.handle_login(message, client_ip)
        elif action == 'get_online_users':
            return self.handle_get_online_users()
        elif action == 'ping':
            return {'success': True, 'message': 'pong'}
        else:
            return {'success': False, 'message': f'Unknown action: {action}'}
    
    def handle_registration(self, message, client_ip):
        """Handle user registration"""
        try:
            username = message.get('username', '').strip()
            password = message.get('password', '')
            
            # Basic validation
            if not username or not password:
                self.db.log_connection_event(None, 'REGISTER_FAILED', client_ip, False, 'Missing credentials')
                return {'success': False, 'message': 'Username and password required'}
            
            if len(username) < 3 or len(username) > 20:
                return {'success': False, 'message': 'Username must be 3-20 characters'}
            
            if len(password) < 6:
                return {'success': False, 'message': 'Password must be at least 6 characters'}
            
            # Register user
            user_id = self.db.register_user(username, password)
            
            if user_id:
                self.db.log_connection_event(user_id, 'REGISTER_SUCCESS', client_ip, True, f'Username: {username}')
                return {'success': True, 'message': 'User registered successfully'}
            else:
                self.db.log_connection_event(None, 'REGISTER_FAILED', client_ip, False, f'Username taken: {username}')
                return {'success': False, 'message': 'Username already exists'}
                
        except Exception as e:
            logger.error(f"❌ Registration error: {e}")
            return {'success': False, 'message': 'Registration failed'}
    
    def handle_login(self, message, client_ip):
        """Handle user login"""
        try:
            username = message.get('username', '').strip()
            password = message.get('password', '')
            
            if not username or not password:
                self.db.log_connection_event(None, 'LOGIN_FAILED', client_ip, False, 'Missing credentials')
                return {'success': False, 'message': 'Username and password required'}
            
            # Authenticate user
            user_data = self.db.authenticate_user(username, password)
            
            if user_data:
                # Generate session token
                import os
                session_token = os.urandom(32).hex()
                
                # Create session
                session_id = self.db.create_session(user_data['id'], session_token, client_ip)
                
                if session_id:
                    self.db.log_connection_event(user_data['id'], 'LOGIN_SUCCESS', client_ip, True, f'Session: {session_id}')
                    return {
                        'success': True,
                        'message': 'Login successful',
                        'user_data': user_data,
                        'session_token': session_token
                    }
            
            self.db.log_connection_event(None, 'LOGIN_FAILED', client_ip, False, f'Invalid credentials: {username}')
            return {'success': False, 'message': 'Invalid username or password'}
            
        except Exception as e:
            logger.error(f"❌ Login error: {e}")
            return {'success': False, 'message': 'Login failed'}
    
    def handle_get_online_users(self):
        """Get list of online users"""
        try:
            online_users = self.db.get_online_users()
            return {
                'success': True,
                'online_users': online_users,
                'count': len(online_users)
            }
        except Exception as e:
            logger.error(f"❌ Error getting online users: {e}")
            return {'success': False, 'message': 'Failed to get online users'}

def main():
    """Main function"""
    print("🚀 Starting Phase 1: Basic Infrastructure")
    print("Features: Database + Multi-client + User Management")
    
    try:
        server = BasicMessagingServer()
        server.start_server()
    except KeyboardInterrupt:
        print("\n🛑 Server shutdown requested")
    except Exception as e:
        print(f"💥 Server error: {e}")
    finally:
        print("🔌 Basic server stopped")

if __name__ == "__main__":
    main()