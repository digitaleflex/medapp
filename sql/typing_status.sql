CREATE TABLE IF NOT EXISTS typing_status (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    receiver_id INT NOT NULL,
    sender_type ENUM('patient', 'medecin') NOT NULL,
    is_typing TINYINT(1) NOT NULL DEFAULT 0,
    last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_typing_status (user_id, receiver_id, sender_type),
    INDEX idx_last_updated (last_updated)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci; 