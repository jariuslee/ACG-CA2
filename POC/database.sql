-- Phase 1: Simple Database Setup
-- IT2504 Applied Cryptography Assignment 2
-- Basic tables for user management and session tracking

-- Create database
CREATE DATABASE IF NOT EXISTS acg_ca2;
USE acg_ca2;

-- Simple users table for Phase 1
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(64) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_online BOOLEAN DEFAULT FALSE,
    
    -- Indexes for performance
    INDEX idx_username (username),
    INDEX idx_online (is_online)
);

-- Simple sessions table for tracking active connections
CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(64) UNIQUE NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Foreign key constraint
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    
    -- Indexes for performance
    INDEX idx_session_token (session_token),
    INDEX idx_user_active (user_id, is_active)
);

-- Basic connection log for audit trail
CREATE TABLE IF NOT EXISTS connection_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    success BOOLEAN NOT NULL,
    message TEXT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign key constraint
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    -- Indexes for performance
    INDEX idx_timestamp (timestamp),
    INDEX idx_action (action),
    INDEX idx_success (success)
);

-- Create a simple view for active users
CREATE VIEW active_users AS
SELECT 
    u.id,
    u.username,
    u.created_at,
    u.last_login,
    COUNT(s.id) as active_sessions
FROM users u
LEFT JOIN sessions s ON u.id = s.user_id AND s.is_active = TRUE
WHERE u.is_online = TRUE
GROUP BY u.id, u.username, u.created_at, u.last_login
ORDER BY u.last_login DESC;

-- Create a view for connection statistics
CREATE VIEW connection_stats AS
SELECT 
    DATE(timestamp) as date,
    action,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN success = TRUE THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN success = FALSE THEN 1 ELSE 0 END) as failed,
    COUNT(DISTINCT ip_address) as unique_ips
FROM connection_log
GROUP BY DATE(timestamp), action
ORDER BY date DESC, total_attempts DESC;

-- Insert some sample data for testing (optional)
-- Uncomment the following lines if you want test data

/*
-- Sample users for testing
INSERT INTO users (username, password_hash, salt) VALUES
('alice', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'testsalt1'),
('bob', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'testsalt2'),
('charlie', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'testsalt3');
-- Note: All passwords are 'password' for testing

-- Sample connection log entries
INSERT INTO connection_log (user_id, action, ip_address, success, message) VALUES
(1, 'REGISTER_SUCCESS', '127.0.0.1', TRUE, 'Username: alice'),
(2, 'REGISTER_SUCCESS', '127.0.0.1', TRUE, 'Username: bob'),
(3, 'REGISTER_SUCCESS', '127.0.0.1', TRUE, 'Username: charlie'),
(1, 'LOGIN_SUCCESS', '127.0.0.1', TRUE, 'Session created'),
(2, 'LOGIN_SUCCESS', '127.0.0.1', TRUE, 'Session created');
*/

-- Stored procedure to clean up inactive sessions
DELIMITER //
CREATE PROCEDURE CleanupInactiveSessions()
BEGIN
    -- Mark old sessions as inactive (older than 1 hour)
    UPDATE sessions 
    SET is_active = FALSE 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR) 
    AND is_active = TRUE;
    
    -- Set users offline if they have no active sessions
    UPDATE users u
    SET is_online = FALSE
    WHERE u.id NOT IN (
        SELECT DISTINCT user_id 
        FROM sessions 
        WHERE is_active = TRUE
    );
    
    -- Return number of cleaned up sessions
    SELECT ROW_COUNT() as sessions_cleaned;
END //
DELIMITER ;

-- Stored procedure to get user statistics
DELIMITER //
CREATE PROCEDURE GetUserStats()
BEGIN
    SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN is_online = TRUE THEN 1 END) as online_users,
        COUNT(CASE WHEN last_login >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as active_last_24h,
        COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as new_last_week
    FROM users;
END //
DELIMITER ;

-- Function to check if username is available
DELIMITER //
CREATE FUNCTION IsUsernameAvailable(check_username VARCHAR(50))
RETURNS BOOLEAN
READS SQL DATA
DETERMINISTIC
BEGIN
    DECLARE user_count INT DEFAULT 0;
    
    SELECT COUNT(*) INTO user_count 
    FROM users 
    WHERE username = check_username;
    
    RETURN (user_count = 0);
END //
DELIMITER ;

-- Display setup completion message
SELECT 'Phase 1 Database setup completed successfully!' AS status;

-- Display current table information
SELECT 'Current Tables:' AS info;
SHOW TABLES;

-- Display table structures
SELECT 'Users Table Structure:' AS info;
DESCRIBE users;

SELECT 'Sessions Table Structure:' AS info;
DESCRIBE sessions;

SELECT 'Connection Log Table Structure:' AS info;
DESCRIBE connection_log;