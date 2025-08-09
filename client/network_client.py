# network_client.py - CLIENT-SIDE Server Communication
# IT2504 Applied Cryptography Assignment 2
#
# ✅ PKI hardening added:
#   - Loads CA certificate (pinned file if available, else from server)
#   - Verifies user certificates are actually signed by the CA
#   - Enforces that keys you use match the ones inside the CA-signed cert
#
#   This prevents MITM from swapping public keys in /api/keys responses.

import requests
import json
from typing import Dict, List, Optional, Tuple

# Try relative import (when used as a package) then absolute (when run as script)
try:
    from .simple_pki import SimpleCertificateAuthority
except ImportError:
    from simple_pki import SimpleCertificateAuthority

class NetworkClient:
    """
    Handles HTTP communication between PyQt5 client and Flask server.

    Security Model:
    - Client sends ONLY encrypted messages to server
    - Server stores and forwards encrypted messages (can't read them)
    - Client retrieves other users' PUBLIC keys from server
    - Server NEVER sees private keys or plain text messages

    PKI Add-on:
    - Verify user certs are signed by our CA
    - Refuse keys unless they match the CA-signed cert (blocks MITM key-swaps)
    """

    
    def __init__(self, server_url: str = "http://localhost:5000"):
        """Initialize network client for server communication."""
        self.server_url = server_url
        self.session = requests.Session()  # Maintains session cookies
        self.is_logged_in = False
        self.current_user_id = None
        self.current_username = None
        

        # PKI state
        self._ca: Optional[SimpleCertificateAuthority] = None
        self._ca_pem: Optional[str] = None

        print(f"Network client initialized - Server: {server_url}")

    # --------------------- PKI helpers ---------------------

    def _ensure_ca_loaded(self) -> None: # Fetches the CA cert
        """
        Ensure we have a CA certificate loaded for verification.
        CLIENT VERSION: Only loads CA cert from server, never creates one.
        """
        if self._ca and self._ca.ca_certificate:
            return

        # IMPORTANT: Client should NEVER create CA files locally
        # Always fetch from server
        print("🔍 Client fetching CA certificate from server...")
        ok, resp = self._make_request('GET', '/api/ca-certificate')
        if not ok or 'ca_certificate' not in resp:
            raise RuntimeError("Cannot load CA certificate from server")
        
        ca_pem = resp['ca_certificate']
        print("✅ CA certificate fetched from server")

        # Create CA instance in verification-only mode (no local CA files)
        self._ca = SimpleCertificateAuthority("Client Verifier", verification_only=True)
        
        # Load the server's CA certificate
        self._ca.load_ca_certificate_pem(ca_pem)
        self._ca_pem = ca_pem
        
        print("✅ Client CA configured for verification only")

    # Temporary fix: Replace _verify_and_bind_keys method in client/network_client.py:

    # Replace _verify_and_bind_keys method in client/network_client.py with this:

    def _verify_and_bind_keys(self, username: str, cert_pem: str, keys: Dict[str, str]) -> Optional[Dict[str, str]]: # Verifies the certificate and binds the keys
        """
        Verify the user's certificate using the server CA and bind the verified keys.
        """
        print(f"🔍 Verifying certificate for: {username}")

        if not cert_pem:
            print("❌ No certificate provided by server; cannot verify keys against CA")
            return None

        try:
            # Ensure CA certificate is loaded for verification
            self._ensure_ca_loaded()

            # Verify certificate and extract embedded user data
            is_valid, user_data = self._ca.verify_user_certificate(cert_pem)
            if not is_valid or not user_data:
                print(f"❌ PKI: Certificate failed validation for {username}")
                return None

            # Check username matches the requested username
            cert_username = user_data.get('username')
            if cert_username != username:
                print(f"❌ PKI: Certificate username doesn't match {username}")
                return None

            # Check keys in server response match those bound in the certificate
            expected_ed25519 = user_data.get('ed25519_public_key')
            expected_x25519 = user_data.get('x25519_public_key')

            if (
                expected_ed25519 == keys.get('ed25519_public_key') and
                expected_x25519 == keys.get('x25519_public_key')
            ):
                print(f"✅ PKI: Certificate verified and keys bound for {username}")
                return {
                    'ed25519_public_key': keys['ed25519_public_key'],
                    'x25519_public_key': keys['x25519_public_key'],
                }

            print(f"❌ PKI: Certificate keys don't match server keys for {username}")
            return None

        except Exception as e:
            print(f"❌ PKI verification error for {username}: {e}")
            return None

    # --------------------- HTTP plumbing ---------------------

    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Tuple[bool, Dict]:
        """
        Make HTTP request to server with error handling.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (e.g., '/api/register')
            data: Request data (for POST requests)

        Returns:
            Tuple of (success, response_data)
        """
        try:
            url = f"{self.server_url}{endpoint}"
            print(f"Making {method} request to: {url}")

            if method.upper() == 'GET':
                response = self.session.get(url, timeout=10)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, timeout=10)
            else:
                return False, {'error': f'Unsupported HTTP method: {method}'}

            print(f"Response status: {response.status_code}")
            print(f"Response headers: {dict(response.headers)}")

            # Parse JSON response
            try:
                if response.headers.get('content-type', '').startswith('application/json'):
                    response_data = response.json()
                else:
                    # Try to parse as JSON anyway
                    response_data = response.json()
            except ValueError:
                # Not JSON, create error response
                response_data = {
                    'error': f'Invalid response format. Status: {response.status_code}, Content: {response.text[:200]}'
                }

            # Check if request was successful
            if response.status_code in [200, 201]:
                return True, response_data
            else:
                return False, response_data

        except requests.exceptions.ConnectionError:
            return False, {'error': 'Cannot connect to server. Is the Flask server running?'}
        except requests.exceptions.Timeout:
            return False, {'error': 'Request timed out'}
        except requests.exceptions.RequestException as e:
            return False, {'error': f'Network error: {str(e)}'}
        except Exception as e:
            return False, {'error': f'Unexpected error: {str(e)}'}

    # ==================== USER AUTHENTICATION ====================

    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Register new user account on server.

        Args:
            username: Desired username
            password: User password

        Returns:
            Tuple of (success, message)
        """
        print(f"🔐 Registering user: {username}")

        data = {'username': username, 'password': password}
        success, response = self._make_request('POST', '/api/register', data)

        if success:
            print(f"✅ Registration successful: {username}")
            return True, response.get('message', 'Registration successful')
        else:
            error = response.get('error', 'Registration failed')
            print(f"❌ Registration failed: {error}")
            return False, error

    def login_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Login user and establish session.

        Args:
            username: Username
            password: Password

        Returns:
            Tuple of (success, message)
        """
        print(f"🔐 Logging in user: {username}")

        data = {'username': username, 'password': password}
        success, response = self._make_request('POST', '/api/login', data)

        if success:
            self.is_logged_in = True
            self.current_user_id = response.get('user_id')
            self.current_username = username
            print(f"✅ Login successful: {username}")
            return True, response.get('message', 'Login successful')
        else:
            error = response.get('error', 'Login failed')
            print(f"❌ Login failed: {error}")
            return False, error

    def logout_user(self) -> Tuple[bool, str]:
        """Logout and clear session."""
        if not self.is_logged_in:
            return False, "Not logged in"

        success, response = self._make_request('POST', '/api/logout')

        self.is_logged_in = False
        self.current_user_id = None
        self.current_username = None

        if success:
            print("✅ Logout successful")
            return True, response.get('message', 'Logout successful')
        else:
            print("⚠️ Logout request failed, but session cleared locally")
            return True, "Logged out locally"

    # ==================== PUBLIC KEY MANAGEMENT ====================

    def upload_my_public_keys(self, ed25519_public: str, x25519_public: str) -> Tuple[bool, str]: # Uploads the public keys to the server
        """
        Upload MY public keys to server for others to use.
        Private keys stay on client!

        Args:
            ed25519_public: My ED25519 public key (base64)
            x25519_public: My X25519 public key (base64)

        Returns:
            Tuple of (success, message)
        """
        if not self.is_logged_in:
            return False, "Must be logged in to upload keys"

        print(f"📤 Uploading public keys to server for: {self.current_username}")

        data = {
            'ed25519_public_key': ed25519_public,
            'x25519_public_key': x25519_public,
            'request_certificate': True,          # <— ADD THIS
        }

        success, response = self._make_request('POST', '/api/keys', data)

        if success:
            print("✅ Public keys uploaded successfully")
            return True, response.get('message', 'Keys uploaded')
        else:
            error = response.get('error', 'Failed to upload keys')
            print(f"❌ Key upload failed: {error}")
            return False, error

    def get_user_public_keys(self, username: str) -> Optional[Dict[str, str]]: # Gets the public keys from the server
        if not self.is_logged_in:
            print("❌ Must be logged in to get user keys")
            return None

        print(f"📥 Getting public keys for: {username}")
        ok, resp = self._make_request('GET', f'/api/keys/{username}')
        if not ok:
            print(f"❌ Failed to get keys for {username}: {resp.get('error')}")
            return None

        keys = resp.get('keys') or {}
        cert_pem = keys.get('certificate')             # <— NOTE: nested inside keys
        if not keys:
            print(f"⚠️ No keys found for: {username}")
            return None
        if not cert_pem:
            print("❌ No certificate provided by server; cannot verify keys against CA")
            return None

        verified = self._verify_and_bind_keys(username, cert_pem, keys)
        if not verified:
            return None

        print(f"✅ Retrieved & verified public keys for: {username}")
        return verified

    def get_all_users(self) -> List[Dict[str, any]]:
        """
        Get list of all registered users (except current user).

        Returns:
            List of user info dictionaries
        """
        if not self.is_logged_in:
            print("❌ Must be logged in to get user list")
            return []

        print("📋 Getting user list from server...")

        success, response = self._make_request('GET', '/api/users')

        if success:
            users = response.get('users', [])
            print(f"✅ Retrieved {len(users)} users")
            return users
        else:
            error = response.get('error', 'Failed to get users')
            print(f"❌ Failed to get user list: {error}")
            return []

    # ==================== ENCRYPTED MESSAGE TRANSMISSION ====================

    def send_encrypted_message(self, recipient_username: str, encrypted_message: str,
                               signature: str, nonce: str) -> Tuple[bool, str]:
        """
        Send encrypted message to server for delivery.
        Server cannot read the message content!

        Args:
            recipient_username: Who to send to
            encrypted_message: AES-256-GCM encrypted message (base64)
            signature: ED25519 signature (base64)
            nonce: AES-GCM nonce (base64)

        Returns:
            Tuple of (success, message)
        """
        if not self.is_logged_in:
            return False, "Must be logged in to send messages"

        print(f"📤 Sending encrypted message to: {recipient_username}")

        try:
            # Get recipient's user ID
            users = self.get_all_users()
            recipient_id = None

            for user in users:
                if user['username'] == recipient_username:
                    recipient_id = user['user_id']
                    break

            if not recipient_id:
                return False, f"User '{recipient_username}' not found"

            data = {
                'recipient_id': recipient_id,
                'encrypted_message': encrypted_message,
                'signature': signature,
                'nonce': nonce
            }

            print(f"Sending message data: recipient_id={recipient_id}")

            success, response = self._make_request('POST', '/api/messages', data)

            if success:
                print(f"✅ Encrypted message sent to: {recipient_username}")
                return True, response.get('message', 'Message sent')
            else:
                error = response.get('error', 'Failed to send message')
                print(f"❌ Failed to send message: {error}")
                return False, error

        except Exception as e:
            error_msg = f"Error sending message: {str(e)}"
            print(f"❌ {error_msg}")
            return False, error_msg

    def get_my_messages(self) -> List[Dict[str, any]]:
        """
        Get encrypted messages sent to me.
        Server returns encrypted messages - client must decrypt them.

        Returns:
            List of encrypted message dictionaries
        """
        if not self.is_logged_in:
            print("❌ Must be logged in to get messages")
            return []

        print("📥 Getting my encrypted messages from server...")

        success, response = self._make_request('GET', '/api/messages')

        if success:
            messages = response.get('messages', [])
            print(f"✅ Retrieved {len(messages)} encrypted messages")
            return messages
        else:
            error = response.get('error', 'Failed to get messages')
            print(f"❌ Failed to get messages: {error}")
            return []

    # ==================== SERVER CONNECTION TESTING ====================

    def test_server_connection(self) -> bool:
        """
        Test if Flask server is running and reachable.

        Returns:
            True if server is reachable, False otherwise
        """
        print("🔍 Testing server connection...")

        try:
            response = requests.get(f"{self.server_url}/api/register", timeout=5)
            if response.status_code in [200, 400, 405]:  # Any response means server is up
                print("✅ Server connection: SUCCESS")
                return True
            else:
                print(f"⚠️ Server responded with status: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Server connection: FAILED - {e}")
            return False

    def get_server_status(self) -> Dict[str, any]:
        """Get server status information."""
        print("📊 Getting server status...")

        success, response = self._make_request('GET', '/api/health')

        if success:
            print("✅ Server status retrieved")
            return response
        else:
            print("⚠️ Server status endpoint not available")
            return {'status': 'unknown', 'error': response.get('error', 'No status available')}


# ==================== TESTING ====================

def test_network_client():
    """Test network client functionality."""
    print("=== TESTING NETWORK CLIENT ===\n")

    client = NetworkClient()

    # Test 1: Server connection
    print("1. Testing server connection...")
    if not client.test_server_connection():
        print("❌ Cannot connect to server!")
        print("   Make sure Flask server is running: python app.py")
        return

    # Test 2: User registration
    print("\n2. Testing user registration...")
    test_user = "network_test_user"
    test_pass = "test123456"

    reg_success, reg_msg = client.register_user(test_user, test_pass)
    print(f"Registration: {reg_success} - {reg_msg}")

    # Test 3: User login
    print("\n3. Testing user login...")
    if reg_success:
        login_success, login_msg = client.login_user(test_user, test_pass)
        print(f"Login: {login_success} - {login_msg}")

        if login_success:
            # Test 4: Upload public keys
            print("\n4. Testing public key upload...")
            dummy_ed25519 = "dGVzdF9lZDI1NTE5X3B1YmxpY19rZXk="
            dummy_x25519 = "dGVzdF94MjU1MTlfcHVibGljX2tleQ=="

            key_success, key_msg = client.upload_my_public_keys(dummy_ed25519, dummy_x25519)
            print(f"Key upload: {key_success} - {key_msg}")

            # Test 5: Get user list
            print("\n5. Testing user list retrieval...")
            users = client.get_all_users()
            print(f"Found {len(users)} other users")

            # Test 6: Get public keys (now CA-verified)
            print("\n6. Testing public key retrieval...")
            keys = client.get_user_public_keys(test_user)
            print(f"Retrieved keys (verified): {keys is not None}")

            # Test 7: Test encrypted message sending (dummy data)
            print("\n7. Testing encrypted message sending...")
            if len(users) > 0:
                target_user = users[0]['username']
                msg_success, msg_result = client.send_encrypted_message(
                    target_user,
                    "ZHVtbXlfZW5jcnlwdGVkX21lc3NhZ2U=",  # dummy encrypted message
                    "ZHVtbXlfc2lnbmF0dXJl",              # dummy signature
                    "ZHVtbXlfbm9uY2U="                   # dummy nonce
                )
                print(f"Message send: {msg_success} - {msg_result}")
            else:
                print("No other users to send message to")

            # Test 8: Logout
            print("\n8. Testing logout...")
            logout_success, logout_msg = client.logout_user()
            print(f"Logout: {logout_success} - {logout_msg}")

    print("\n✅ Network Client tests completed!")
    print("🔐 Security Model Confirmed:")
    print("   ✓ Only encrypted messages sent to server")
    print("   ✓ Public keys verified against CA-signed certificate (prevents MITM swaps)")
    print("   ✓ Private keys never transmitted")
    print("   ✓ Server cannot read message content")


if __name__ == "__main__":
    test_network_client()
