-- Phase 1: Complete Database Setup for IT2504 Applied Cryptography Assignment 2
-- Secure Messaging System - Basic Infrastructure
-- Authors: [Your Names Here]

-- Create database
CREATE DATABASE IF NOT EXISTS acg_ca2;
USE acg_ca2;

-- =====================================================
-- MAIN TABLES
-- =====================================================

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
    INDEX idx_online (is_online),
    INDEX idx_created (created_at)
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
    INDEX idx_user_active (user_id, is_active),
    INDEX idx_created (created_at)
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
    INDEX idx_success (success),
    INDEX idx_ip (ip_address)
);

-- =====================================================
-- VIEWS FOR EASY QUERYING
-- =====================================================

-- Create a view for active users with session info
CREATE OR REPLACE VIEW active_users AS
SELECT 
    u.id,
    u.username,
    u.created_at,
    u.last_login,
    u.is_online,
    COUNT(s.id) as active_sessions,
    GROUP_CONCAT(s.client_ip SEPARATOR ', ') as client_ips
FROM users u
LEFT JOIN sessions s ON u.id = s.user_id AND s.is_active = TRUE
WHERE u.is_online = TRUE
GROUP BY u.id, u.username, u.created_at, u.last_login, u.is_online
ORDER BY u.last_login DESC;

-- Create a view for connection statistics by date
CREATE OR REPLACE VIEW connection_stats AS
SELECT 
    DATE(timestamp) as date,
    action,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN success = TRUE THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN success = FALSE THEN 1 ELSE 0 END) as failed,
    COUNT(DISTINCT ip_address) as unique_ips,
    COUNT(DISTINCT user_id) as unique_users
FROM connection_log
GROUP BY DATE(timestamp), action
ORDER BY date DESC, total_attempts DESC;

-- Create a view for session summary
CREATE OR REPLACE VIEW session_summary AS
SELECT 
    s.id as session_id,
    u.username,
    s.session_token,
    s.client_ip,
    s.created_at,
    s.is_active,
    CASE 
        WHEN s.is_active = TRUE THEN 'Active'
        ELSE 'Inactive'
    END AS status,
    TIMESTAMPDIFF(MINUTE, s.created_at, NOW()) as duration_minutes
FROM sessions s
JOIN users u ON s.user_id = u.id
ORDER BY s.created_at DESC;

-- =====================================================
-- STORED PROCEDURES FOR MAINTENANCE
-- =====================================================

-- Stored procedure to clean up inactive sessions
DELIMITER //
CREATE PROCEDURE CleanupInactiveSessions()
BEGIN
    DECLARE sessions_cleaned INT DEFAULT 0;
    
    -- Mark old sessions as inactive (older than 1 hour)
    UPDATE sessions 
    SET is_active = FALSE 
    WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR) 
    AND is_active = TRUE;
    
    SET sessions_cleaned = ROW_COUNT();
    
    -- Set users offline if they have no active sessions
    UPDATE users u
    SET is_online = FALSE
    WHERE u.id NOT IN (
        SELECT DISTINCT user_id 
        FROM sessions 
        WHERE is_active = TRUE
    );
    
    -- Return results
    SELECT 
        sessions_cleaned as sessions_cleaned,
        (SELECT COUNT(*) FROM users WHERE is_online = TRUE) as users_still_online,
        NOW() as cleanup_time;
END //
DELIMITER ;

-- Stored procedure to get comprehensive user statistics
DELIMITER //
CREATE PROCEDURE GetUserStats()
BEGIN
    SELECT 
        'User Statistics' as category,
        COUNT(*) as total_users,
        COUNT(CASE WHEN is_online = TRUE THEN 1 END) as online_users,
        COUNT(CASE WHEN last_login >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as active_last_24h,
        COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as new_last_week,
        COUNT(CASE WHEN last_login IS NULL THEN 1 END) as never_logged_in
    FROM users
    
    UNION ALL
    
    SELECT 
        'Session Statistics' as category,
        COUNT(*) as total_sessions,
        COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_sessions,
        COUNT(DISTINCT user_id) as unique_users_with_sessions,
        COUNT(DISTINCT client_ip) as unique_client_ips,
        0 as unused_field
    FROM sessions
    
    UNION ALL
    
    SELECT 
        'Activity Statistics' as category,
        COUNT(*) as total_log_entries,
        COUNT(CASE WHEN success = TRUE THEN 1 END) as successful_actions,
        COUNT(CASE WHEN action = 'LOGIN_SUCCESS' THEN 1 END) as successful_logins,
        COUNT(CASE WHEN action = 'REGISTER_SUCCESS' THEN 1 END) as successful_registrations,
        COUNT(DISTINCT ip_address) as unique_ips_in_logs
    FROM connection_log;
END //
DELIMITER ;

-- =====================================================
-- UTILITY FUNCTIONS
-- =====================================================

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

-- Function to get user online status
DELIMITER //
CREATE FUNCTION GetUserOnlineStatus(check_username VARCHAR(50))
RETURNS VARCHAR(20)
READS SQL DATA
DETERMINISTIC
BEGIN
    DECLARE online_status BOOLEAN DEFAULT FALSE;
    
    SELECT is_online INTO online_status
    FROM users 
    WHERE username = check_username;
    
    IF online_status IS NULL THEN
        RETURN 'User Not Found';
    ELSEIF online_status = TRUE THEN
        RETURN 'Online';
    ELSE
        RETURN 'Offline';
    END IF;
END //
DELIMITER ;

-- =====================================================
-- SAMPLE DATA FOR TESTING (OPTIONAL)
-- =====================================================

-- Uncomment the following section if you want sample test data

/*
-- Sample users for testing (password is 'password123' for all)
INSERT INTO users (username, password_hash, salt) VALUES
('testuser1', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'testsalt1'),
('testuser2', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'testsalt2'),
('testuser3', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'testsalt3');

-- Sample connection log entries
INSERT INTO connection_log (user_id, action, ip_address, success, message) VALUES
(1, 'REGISTER_SUCCESS', '127.0.0.1', TRUE, 'Username: testuser1'),
(2, 'REGISTER_SUCCESS', '192.168.21.100', TRUE, 'Username: testuser2'),
(3, 'REGISTER_SUCCESS', '192.168.21.101', TRUE, 'Username: testuser3'),
(1, 'LOGIN_SUCCESS', '127.0.0.1', TRUE, 'Session created'),
(2, 'LOGIN_SUCCESS', '192.168.21.100', TRUE, 'Session created'),
(NULL, 'LOGIN_FAILED', '192.168.21.102', FALSE, 'Invalid credentials: wronguser');

-- Sample sessions
INSERT INTO sessions (user_id, session_token, client_ip) VALUES
(1, 'sample_token_1234567890abcdef', '127.0.0.1'),
(2, 'sample_token_abcdef1234567890', '192.168.21.100');

-- Update users to online status
UPDATE users SET is_online = TRUE, last_login = NOW() WHERE id IN (1, 2);
*/

-- =====================================================
-- VERIFICATION QUERIES
-- =====================================================

-- Display setup completion message
SELECT 'Phase 1 Database setup completed successfully!' AS status, NOW() as setup_time;

-- Show created tables
SELECT 'Created Tables:' AS info;
SHOW TABLES;

-- Show table structures
SELECT 'Users Table Structure:' AS info;
DESCRIBE users;

SELECT 'Sessions Table Structure:' AS info;
DESCRIBE sessions;

SELECT 'Connection Log Table Structure:' AS info;
DESCRIBE connection_log;

-- Show created views
SELECT 'Created Views:' AS info;
SHOW FULL TABLES WHERE TABLE_TYPE LIKE 'VIEW';

-- Show created procedures
SELECT 'Created Procedures:' AS info;
SHOW PROCEDURE STATUS WHERE Db = 'acg_ca2';

-- Show created functions
SELECT 'Created Functions:' AS info;
SHOW FUNCTION STATUS WHERE Db = 'acg_ca2';

-- Final verification
SELECT 
    'Database Ready!' as message,
    (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'acg_ca2' AND table_type = 'BASE TABLE') as tables_created,
    (SELECT COUNT(*) FROM information_schema.views WHERE table_schema = 'acg_ca2') as views_created,
    (SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema = 'acg_ca2' AND routine_type = 'PROCEDURE') as procedures_created,
    (SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema = 'acg_ca2' AND routine_type = 'FUNCTION') as functions_created;