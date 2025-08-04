# app.py - Simplified Flask Server
# IT2504 Applied Cryptography Assignment 2

from flask import Flask, request, jsonify, session
import secrets
from database import DatabaseManager

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Initialize database
db = DatabaseManager(password='1qwer$#@!')  

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

@app.route('/api/users', methods=['GET'])
def get_users():
    """Get list of users."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    users = db.get_users(session['user_id'])
    return jsonify({'users': users}), 200

@app.route('/api/keys/<username>', methods=['GET'])
def get_keys(username):
    """Get public keys for user."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    keys = db.get_public_keys(username)
    if keys:
        return jsonify({'keys': keys}), 200
    else:
        return jsonify({'error': 'Keys not found'}), 404

@app.route('/api/keys', methods=['POST'])
def store_keys():
    """Store public keys."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    ed25519_key = data.get('ed25519_public_key')
    x25519_key = data.get('x25519_public_key')
    
    if not ed25519_key or not x25519_key:
        return jsonify({'error': 'Both keys required'}), 400
    
    success = db.store_public_keys(session['user_id'], ed25519_key, x25519_key)
    
    if success:
        return jsonify({'message': 'Keys stored'}), 200
    else:
        return jsonify({'error': 'Failed to store keys'}), 500

@app.route('/api/messages', methods=['POST'])
def send_message():
    """Store encrypted message."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    recipient_id = data.get('recipient_id')
    encrypted_message = data.get('encrypted_message')
    signature = data.get('signature')
    nonce = data.get('nonce')
    
    success = db.store_message(
        session['user_id'], recipient_id, encrypted_message, signature, nonce
    )
    
    if success:
        return jsonify({'message': 'Message sent'}), 200
    else:
        return jsonify({'error': 'Failed to send message'}), 500

if __name__ == '__main__':
    if db.connect():
        print("Starting server...")
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        print("Failed to connect to database")