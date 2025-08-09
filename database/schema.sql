-- Simplified MySQL Schema for Secure Messaging System
-- IT2504 Applied Cryptography Assignment 2

CREATE DATABASE IF NOT EXISTS secure_messaging2;
USE secure_messaging2;

-- Users table
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(64) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Public keys table (for ED25519 and X25519)
CREATE TABLE public_keys (
    key_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    ed25519_public_key TEXT NOT NULL,    -- For digital signatures
    x25519_public_key TEXT NOT NULL,     -- For ECDH key exchange
    certificate TEXT NULL,               -- PKI certificate for this key pair
    key_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Messages table (encrypted with AES-256-GCM)
CREATE TABLE messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    recipient_id INT NOT NULL,
    encrypted_message TEXT NOT NULL,     -- AES-256-GCM encrypted
    message_signature TEXT NOT NULL,    -- ED25519 signature
    nonce VARCHAR(32) NOT NULL,         -- AES-GCM nonce
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(user_id),
    FOREIGN KEY (recipient_id) REFERENCES users(user_id)
);

-- Show tables
SHOW TABLES;