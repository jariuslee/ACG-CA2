# app.py - Complete Flask Server with SECURE PKI Support
# IT2504 Applied Cryptography Assignment 2 - SECURITY FIXED

from flask import Flask, request, jsonify, session
import secrets
import sys
import os
from database import DatabaseManager

# Add client directory to path for PKI imports
from simple_pki import SimpleCertificateAuthority

# Import PKI safely
try:
    from simple_pki import SimpleCertificateAuthority
    PKI_AVAILABLE = True
except ImportError:
    print("⚠️ PKI module not found - running in legacy mode")
    PKI_AVAILABLE = False
    SimpleCertificateAuthority = None

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Initialize database
db = DatabaseManager(password='Yoyoman123')   # Change password as needed

# Initialize PKI CA
ca = None
if PKI_AVAILABLE:
    try:
        ca = SimpleCertificateAuthority("SecureMessaging Server CA")
        print("✅ PKI Certificate Authority initialized")
    except Exception as e:
        print(f"⚠️ PKI CA initialization failed: {e}")
        ca = None
else:
    print("⚠️ Running without PKI support")

@app.route('/api/health', methods=['GET'])
def health():
    """Simple health check endpoint."""
    return jsonify({'status': 'Server is running!'}), 200

@app.route('/api/register', methods=['POST'])
def register():
    """Register new user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    success, result = db.create_user(username, password)
    
    if success:
        return jsonify({'message': 'User registered', 'user_id': result}), 201
    else:
        return jsonify({'error': result}), 400

@app.route('/api/login', methods=['POST'])
def login():
    """Login user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    success, user_id = db.authenticate_user(username, password)
    
    if success:
        session['user_id'] = user_id
        session['username'] = username
        return jsonify({'message': 'Login successful', 'user_id': user_id}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout user."""
    session.clear()
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/users', methods=['GET'])
def get_users():
    """Get list of users."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    users = db.get_users(session['user_id'])
    return jsonify({'users': users}), 200

# Replace your /api/keys POST route with this debug version:

@app.route('/api/keys', methods=['POST'])
def store_keys():
    """Store public keys with SECURE certificate generation (DEBUG VERSION)."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    ed25519_key = data.get('ed25519_public_key')
    x25519_key = data.get('x25519_public_key')
    request_certificate = data.get('request_certificate', False)
    
    print(f"🔍 DEBUG: Key upload request for user {session['username']}")
    print(f"🔍 DEBUG: request_certificate = {request_certificate}")
    print(f"🔍 DEBUG: PKI_AVAILABLE = {PKI_AVAILABLE}")
    print(f"🔍 DEBUG: ca exists = {ca is not None}")
    
    if not ed25519_key or not x25519_key:
        return jsonify({'error': 'Both keys required'}), 400
    
    # Store keys using existing method
    success = db.store_public_keys(session['user_id'], ed25519_key, x25519_key)
    print(f"🔍 DEBUG: Keys stored successfully = {success}")
    
    if success:
        certificate = None
        
        # Generate certificate if requested and CA available
        if request_certificate and ca and PKI_AVAILABLE:
            try:
                print(f"🔍 DEBUG: Attempting to generate certificate...")
                
                # Check if we have the secure method
                if hasattr(ca, 'issue_user_certificate_authenticated'):
                    print(f"🔍 DEBUG: Using secure method")
                    certificate = ca.issue_user_certificate_authenticated(
                        session['username'], ed25519_key, x25519_key
                    )
                else:
                    print(f"🔍 DEBUG: Using legacy method")
                    certificate = ca.issue_user_certificate(
                        session['username'], ed25519_key, x25519_key
                    )
                
                print(f"🔍 DEBUG: Certificate generated successfully")
                print(f"🔍 DEBUG: Certificate length = {len(certificate) if certificate else 0}")
                
                # Store certificate in database
                cert_stored = db.store_user_certificate(session['user_id'], certificate)
                print(f"🔍 DEBUG: Certificate stored in DB = {cert_stored}")
                
                print(f"✅ Certificate issued for {session['username']}")
                
            except Exception as e:
                print(f"❌ Certificate generation failed: {e}")
                import traceback
                traceback.print_exc()
                # Continue without certificate - not a fatal error
        else:
            print(f"🔍 DEBUG: Certificate not requested or not available")
            print(f"🔍 DEBUG: request_certificate={request_certificate}, ca={ca is not None}, PKI_AVAILABLE={PKI_AVAILABLE}")
        
        message = 'Keys stored with certificate' if certificate else 'Keys stored'
        return jsonify({'message': message, 'certificate': certificate}), 200
    else:
        return jsonify({'error': 'Failed to store keys'}), 500

@app.route('/api/keys/<username>', methods=['GET']) # returns public keys and certificate
def get_keys(username):
    """Get public keys with certificate if available."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    # Get keys using existing method
    keys = db.get_public_keys(username)
    if keys:
        # Add certificate if available
        try:
            certificate = db.get_user_certificate(username)
            if certificate:
                keys['certificate'] = certificate
        except AttributeError:
            # Database method doesn't exist yet - that's okay
            pass
        except Exception as e:
            print(f"⚠️ Error getting certificate: {e}")
        
        return jsonify({'keys': keys}), 200
    else:
        return jsonify({'error': 'Keys not found'}), 404

@app.route('/api/ca-certificate', methods=['GET']) # returns CA certificate, continue after server simple_pki.py
def get_ca_certificate():
    """Get CA certificate for client verification."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if ca and PKI_AVAILABLE:
        try:
            ca_cert_pem = ca.get_ca_certificate_pem()
            return jsonify({'ca_certificate': ca_cert_pem}), 200
        except Exception as e:
            print(f"❌ Error getting CA certificate: {e}")
            return jsonify({'error': 'Failed to get CA certificate'}), 500
    else:
        return jsonify({'error': 'PKI not available'}), 503

@app.route('/api/auth-status', methods=['GET'])
def auth_status():
    """Check authentication status - useful for debugging."""
    if 'user_id' not in session:
        return jsonify({'authenticated': False}), 401
    
    return jsonify({
        'authenticated': True,
        'user_id': session['user_id'],
        'username': session['username']
    }), 200

@app.route('/api/certificate-info/<username>', methods=['GET'])
def certificate_info(username):
    """Get certificate validation information."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if ca and PKI_AVAILABLE:
        try:
            # Get certificate from database
            certificate = db.get_user_certificate(username)
            if certificate:
                # Verify certificate
                is_valid, cert_data = ca.verify_user_certificate(certificate)
                
                return jsonify({
                    'has_certificate': True,
                    'is_valid': is_valid,
                    'certificate_data': cert_data,
                    'username_match': cert_data.get('username') == username if cert_data else False,
                    'authenticated_issuance': cert_data.get('issued_to_authenticated_user', False) if cert_data else False
                }), 200
            else:
                return jsonify({'has_certificate': False}), 404
                
        except Exception as e:
            return jsonify({'error': f'Certificate validation failed: {e}'}), 500
    else:
        return jsonify({'error': 'PKI not available'}), 503

@app.route('/api/messages', methods=['GET', 'POST'])
def messages():
    """Handle messages - GET to retrieve, POST to send."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    if request.method == 'GET':
        # Get messages for current user
        try:
            print(f"Getting messages for user {session['user_id']}")
            messages = db.get_messages(session['user_id'])
            print(f"Found {len(messages)} messages")
            return jsonify({'messages': messages}), 200
        except Exception as e:
            print(f"❌ Error getting messages: {e}")
            return jsonify({'error': 'Failed to get messages'}), 500
    
    elif request.method == 'POST':
        # Send/store new message
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
                
            recipient_id = data.get('recipient_id')
            encrypted_message = data.get('encrypted_message')
            signature = data.get('signature')
            nonce = data.get('nonce')
            
            # Validate required fields
            if not all([recipient_id, encrypted_message, signature, nonce]):
                return jsonify({'error': 'Missing required fields'}), 400
            
            print(f"📤 Storing message from user {session['user_id']} to user {recipient_id}")
            print(f"Data lengths: msg={len(encrypted_message)}, sig={len(signature)}, nonce={len(nonce)}")
            
            success = db.store_message(
                session['user_id'], recipient_id, encrypted_message, signature, nonce
            )
            
            if success:
                print("✅ Message stored successfully")
                return jsonify({'message': 'Message sent successfully'}), 200
            else:
                print("❌ Failed to store message in database")
                return jsonify({'error': 'Failed to send message'}), 500
                
        except Exception as e:
            print(f"❌ Error storing message: {e}")
            return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    if db.connect():
        print("🔒 Server starting with SECURE PKI support...")
        print("✅ Identity spoofing vulnerability FIXED")
        print("✅ Certificates only issued to authenticated users")
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        print("Failed to connect to database")