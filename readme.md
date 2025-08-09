# Secure Messaging System
**IT2504 Applied Cryptography Assignment 2**

## Overview
A secure end-to-end encrypted messaging application implementing military-grade cryptographic protocols. The system features a PyQt5 desktop client communicating with a Flask server backend, ensuring complete message confidentiality through client-side encryption.

## 🔐 Security Features
- **End-to-End Encryption**: Server never sees plaintext messages
- **PKI Certificate Authority**: Prevents man-in-the-middle attacks
- **Perfect Forward Secrecy**: Unique keys per conversation
- **Digital Signatures**: Message authenticity and non-repudiation
- **Local Key Storage**: Private keys never leave client devices

## 🛠 Cryptographic Algorithms
- **AES-256-GCM**: Message encryption with authentication
- **ECDH X25519**: Secure key exchange
- **ED25519**: Digital signatures
- **HKDF**: Key derivation from shared secrets
- **SHA-256**: Password hashing
- **RSA-2048**: PKI certificate signing
- **Secure Random Generation**: Nonces and entropy

## 📋 Prerequisites
- Python 3.8+
- MySQL 8.0+
- PyQt5
- Required Python packages (see requirements.txt)

## ⚙️ Installation

### 1. Clone Repository
```bash
git clone <repository-url>
cd secure-messaging-system
```

### 2. Database Setup
```bash
# Start MySQL service
mysql -u root -p
# Create database using provided schema
source database/schema.sql
```

### 3. Install Dependencies

**Server Dependencies:**
```bash
cd server
pip install -r requirements.txt
```

**Client Dependencies:**
```bash
cd client
pip install -r requirements.txt
```

### 4. Configure Database
Update database credentials in:
- `server/database.py` (line 10)
- Update password in `DatabaseManager` constructor

## 🚀 Running the Application

### 1. Start the Server
```bash
cd server
python app.py
```
Server will start on `http://localhost:5000`

### 2. Start Client(s)
```bash
cd client
python main.py
```

Multiple clients can run simultaneously for testing different users.

## 📁 Project Structure
```
secure-messaging-system/
├── client/
│   ├── main.py              # Application entry point
│   ├── crypto_utils.py      # Cryptographic operations
│   ├── key_manager.py       # Local key storage
│   ├── network_client.py    # Server communication
│   ├── simple_pki.py        # Certificate verification
│   ├── requirements.txt     # Client dependencies
│   └── ui/
│       ├── login_window.py  # Login interface
│       ├── register_window.py # Registration interface
│       └── chat_window.py   # Main chat interface
├── server/
│   ├── app.py              # Flask server
│   ├── database.py         # MySQL operations
│   ├── simple_pki.py       # Certificate Authority
│   ├── requirements.txt    # Server dependencies
│   └── ca_data/           # PKI certificates
├── database/
│   └── schema.sql         # Database schema
├── .env                   # Environment variables
└── README.md
```

## 💬 Usage

### 1. Register New User
- Run client application
- Click "Create Account"
- Enter username and password
- Keys will be generated automatically

### 2. Login and Chat
- Login with credentials
- Select user from online users list
- Type message and click "Send Encrypted"
- Messages are encrypted end-to-end

### 3. Security Verification
- Check message signatures for authenticity
- View encryption status in chat interface
- Private keys stored locally in `client/keys/` directory

## 🔧 Configuration

### Database Settings
Update in `server/database.py`:
```python
def __init__(self, host='localhost', database='secure_messaging2', 
             user='root', password='YOUR_PASSWORD'):
```

### Server Settings
Update in `server/app.py`:
```python
app.run(host='0.0.0.0', port=5000, debug=True)
```

## 🧪 Testing

### Test Cryptographic Functions
```bash
cd client
python crypto_utils.py
```

### Test Network Client
```bash
cd client
python network_client.py
```

### Test Key Manager
```bash
cd client
python key_manager.py
```

## 🛡️ Security Model

### Client-Side Security
- All encryption/decryption occurs on client
- Private keys never transmitted
- Certificate verification before key acceptance
- Secure key derivation for each message

### Server-Side Security
- Blind relay (cannot decrypt messages)
- Session management
- PKI Certificate Authority
- Encrypted data storage only

## 🚨 Troubleshooting

### Common Issues

**Database Connection Error:**
- Ensure MySQL is running
- Check credentials in `database.py`
- Verify database exists

**Key Generation Error:**
- Check file permissions in client directory
- Ensure cryptography library installed correctly

**Server Connection Error:**
- Verify Flask server is running on port 5000
- Check firewall settings
- Ensure no port conflicts

**Certificate Issues:**
- Delete `server/ca_data/` folder to regenerate CA
- Restart server to recreate certificates

## 📄 License
Educational use only - IT2504 Applied Cryptography Assignment

## 👥 Contributors
- Student Name - All components except PKI CA implementation
- Course: IT2504 Applied Cryptography
- Institution: Singapore Polytechnic

## 📚 References
- NIST Cryptographic Standards
- RFC 7748 (X25519 and Ed25519)
- RFC 5869 (HKDF)
- Python Cryptography Documentation