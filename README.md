 # Secure Messaging Service (Python, X25519 + AES-GCM)

This project demonstrates a secure messaging protocol between a client and a server using modern cryptography. It is designed by the GOAT Auntielucy.

## Features
- *Key Exchange:* X25519 (Elliptic Curve Diffie-Hellman over Curve25519)
- *Key Derivation:* HKDF (HMAC-based Key Derivation Function, SHA-256)
- *Encryption:* AES-256-GCM (Authenticated Encryption)
- *No third-party server or cloud: all local communication*

## Files
- server.py — Standalone, fully commented secure server
- client.py — Standalone, fully commented secure client

## Requirements
- Python 3.7+
- [cryptography](https://cryptography.io/en/latest/)

Install dependencies:
sh
pip install cryptography


## How to Run
1. *Open two terminals.*
2. In the first terminal, start the server:
   sh
   python server.py
   
3. In the second terminal, start the client:
   sh
   python client.py
   
4. Enter a message in the client terminal. The server will print the decrypted message and all cryptographic steps.

## How It Works (Step-by-Step)
1. *Key Generation:* Both client and server generate X25519 key pairs.
2. *Key Exchange:* They exchange public keys over the socket.
3. *Shared Secret:* Each side computes a shared secret using ECDH.
4. *Key Derivation:* The client generates a random salt and both sides use HKDF to derive a 256-bit AES key from the shared secret.
5. *Encryption:* The client encrypts a message using AES-256-GCM with a random nonce.
6. *Transmission:* The client sends the salt, nonce, and ciphertext to the server.
7. *Decryption:* The server decrypts the message and prints it.

## Example Output
*Client:*

================ CLIENT STARTED ================
--- Key Generation ---
Client public key:           7f...e2

--- Key Exchange ---
Sent client public key:      7f...e2
Received server's public key: 1a...b3

--- Shared Secret ---
Derived shared secret:       9c...a1

--- Key Derivation ---
Generated salt:              2b...c4
Derived AES-256 key:         8d...f5

Enter message to send: Hello, teacher!

--- Message Encryption ---
Generated nonce:             3e...a7
Ciphertext:                  5c...d2

Message sent securely! The server should print the decrypted message.
==========================================================


*Server:*

================ SERVER STARTED ================
Server listening on 127.0.0.1:65432

---------------- CONNECTION ESTABLISHED ----------------
Connected by: ('127.0.0.1', 54321)

--- Key Exchange ---
Received client's public key: 7f...e2
Sent server's public key:    1a...b3

--- Shared Secret ---
Derived shared secret:       9c...a1

--- Key Derivation ---
Received salt:               2b...c4
Derived AES-256 key:         8d...f5

--- Message Reception ---
Received nonce:              3e...a7
Received ciphertext:         5c...d2

--- Decryption Result ---
Decrypted message from client:
    "Hello, teacher!"

SUCCESS: Secure key exchange and message decryption worked!
==========================================================


## How to Demonstrate
- Walk through each section of the output and code.
- Explain how the keys are generated, exchanged, and used.
- Show how the message is encrypted and decrypted.
- Point out the use of modern, secure cryptography (X25519, HKDF, AES-GCM).

## Security Notes
- No private keys are ever sent over the network.
- Each message uses a random nonce and salt.
- AES-GCM provides both confidentiality and integrity.
- All cryptography is handled using the [cryptography](https://cryptography.io/en/latest/) library.

---

*This project is ideal for demonstrating secure communication and explaining cryptography in a simple, hands-on way.*
