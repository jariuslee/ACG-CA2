#!/usr/bin/env python3
"""
Phase 1: Basic Client
IT2504 Applied Cryptography Assignment 2

Goal: Simple client for testing basic server functionality
- User registration and login
- Connection to server
- Basic message exchange (no crypto yet)
- Multi-client testing

Authors: [Your Names Here]
"""

import socket
import json
import threading
import time

# Configuration
CONFIG = {
    'HOST': '127.0.0.1',
    'PORT': 65432,
    'TIMEOUT': 10
}

class BasicClient:
    """Basic client for Phase 1 testing"""
    
    def __init__(self):
        self.socket = None
        self.user_data = None
        self.session_token = None
        self.running = False
        
    def connect_to_server(self):
        """Connect to the Phase 1 server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(CONFIG['TIMEOUT'])
            self.socket.connect((CONFIG['HOST'], CONFIG['PORT']))
            print(f"✅ Connected to server at {CONFIG['HOST']}:{CONFIG['PORT']}")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def send_message(self, message):
        """Send JSON message to server and get response"""
        try:
            # Send message
            self.socket.send(json.dumps(message).encode())
            
            # Receive response
            response_data = self.socket.recv(1024)
            response = json.loads(response_data.decode())
            
            return response
            
        except Exception as e:
            print(f"❌ Communication error: {e}")
            return {'success': False, 'message': str(e)}
    
    def start_client(self):
        """Start the basic client"""
        print("\n" + "="*50)
        print("🚀 PHASE 1: BASIC CLIENT")
        print("="*50)
        print("📋 Available Actions:")
        print("   1. Register new user")
        print("   2. Login existing user")
        print("   3. Test connection")
        print("   4. Exit")
        print("="*50)
        
        if not self.connect_to_server():
            return
        
        while True:
            print(f"\n📱 CLIENT MENU")
            if self.user_data:
                print(f"👤 Logged in as: {self.user_data['username']}")
            else:
                print("👤 Not logged in")
            
            print("1. 📝 Register")
            print("2. 🔑 Login")
            print("3. 👥 Get online users")
            print("4. 🏓 Ping server")
            print("5. ❌ Exit")
            
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == '1':
                self.register_user()
            elif choice == '2':
                self.login_user()
            elif choice == '3':
                self.get_online_users()
            elif choice == '4':
                self.ping_server()
            elif choice == '5':
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid option")
        
        self.disconnect()
    
    def register_user(self):
        """Register a new user"""
        print(f"\n📝 USER REGISTRATION")
        print("="*30)
        
        username = input("Username (3-20 chars): ").strip()
        password = input("Password (6+ chars): ")
        
        message = {
            'action': 'register',
            'username': username,
            'password': password
        }
        
        response = self.send_message(message)
        
        if response['success']:
            print(f"✅ {response['message']}")
        else:
            print(f"❌ {response['message']}")
    
    def login_user(self):
        """Login existing user"""
        print(f"\n🔑 USER LOGIN")
        print("="*20)
        
        username = input("Username: ").strip()
        password = input("Password: ")
        
        message = {
            'action': 'login',
            'username': username,
            'password': password
        }
        
        response = self.send_message(message)
        
        if response['success']:
            self.user_data = response['user_data']
            self.session_token = response['session_token']
            print(f"✅ Welcome back, {username}!")
            print(f"🎫 Session token: {self.session_token[:16]}...")
        else:
            print(f"❌ {response['message']}")
    
    def get_online_users(self):
        """Get list of online users"""
        if not self.user_data:
            print("❌ Please login first")
            return
            
        message = {'action': 'get_online_users'}
        response = self.send_message(message)
        
        if response['success']:
            users = response['online_users']
            count = response['count']
            print(f"\n👥 Online Users ({count}):")
            if users:
                for i, user in enumerate(users, 1):
                    print(f"   {i}. {user}")
            else:
                print("   No users online")
        else:
            print(f"❌ {response['message']}")
    
    def ping_server(self):
        """Test server connectivity"""
        print("🏓 Pinging server...")
        
        start_time = time.time()
        message = {'action': 'ping'}
        response = self.send_message(message)
        end_time = time.time()
        
        if response['success']:
            latency = (end_time - start_time) * 1000
            print(f"✅ Pong! Latency: {latency:.2f}ms")
        else:
            print(f"❌ Ping failed: {response['message']}")
    
    def disconnect(self):
        """Disconnect from server"""
        if self.socket:
            try:
                self.socket.close()
                print("🔌 Disconnected from server")
            except:
                pass

def run_multiple_clients():
    """Helper function to test multiple clients"""
    print("\n🔄 MULTI-CLIENT TEST MODE")
    print("This will create multiple client instances for testing")
    
    num_clients = int(input("Number of clients to create (1-5): "))
    
    clients = []
    for i in range(num_clients):
        print(f"\n🚀 Starting Client {i+1}")
        client = BasicClient()
        if client.connect_to_server():
            clients.append(client)
            
            # Auto-register and login test users
            test_username = f"testuser{i+1}"
            test_password = "password123"
            
            # Register
            reg_msg = {
                'action': 'register',
                'username': test_username,
                'password': test_password
            }
            reg_response = client.send_message(reg_msg)
            print(f"📝 Registration: {reg_response['message']}")
            
            # Login
            login_msg = {
                'action': 'login',
                'username': test_username,
                'password': test_password
            }
            login_response = client.send_message(login_msg)
            if login_response['success']:
                client.user_data = login_response['user_data']
                client.session_token = login_response['session_token']
                print(f"✅ {test_username} logged in successfully")
    
    # Test getting online users from first client
    if clients:
        print(f"\n👥 Testing online users from Client 1:")
        online_msg = {'action': 'get_online_users'}
        online_response = clients[0].send_message(online_msg)
        if online_response['success']:
            print(f"Online users: {online_response['online_users']}")
    
    # Keep connections alive for testing
    input("\nPress Enter to disconnect all clients...")
    
    # Disconnect all clients
    for i, client in enumerate(clients):
        client.disconnect()
        print(f"🔌 Client {i+1} disconnected")

def main():
    """Main function"""
    print("🚀 Phase 1 Basic Client")
    print("Choose mode:")
    print("1. Single client mode")
    print("2. Multi-client test mode")
    
    choice = input("Select mode (1-2): ").strip()
    
    if choice == '1':
        client = BasicClient()
        client.start_client()
    elif choice == '2':
        run_multiple_clients()
    else:
        print("❌ Invalid choice")

if __name__ == "__main__":
    main()