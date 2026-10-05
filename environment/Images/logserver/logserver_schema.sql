-- ----------------------------
-- Database creation
-- ----------------------------

CREATE DATABASE IF NOT EXISTS cert_archive_db;
CREATE DATABASE IF NOT EXISTS userdb_backup_db;
CREATE DATABASE IF NOT EXISTS log_backup_db; -- create log backup database


-- ----------------------------
-- 1. Certificate Archive DB
-- ----------------------------
USE cert_archive_db; -- pdf p4

CREATE TABLE IF NOT EXISTS archived_certificates (
    serial_number BIGINT PRIMARY KEY,
    uid VARCHAR(32) NOT NULL,
    issue_time DATETIME NOT NULL,

    -- certificate:
    certificate_pem MEDIUMTEXT NOT NULL,
    -- certificate's public key:
    public_key_pem MEDIUMTEXT NOT NULL,

    -- certificate's private key:
    private_key_cipher VARBINARY(4096) NOT NULL,
    enc_algo VARCHAR(32) NOT NULL,
    enc_nonce VARBINARY(32) NOT NULL,
    enc_tag VARBINARY(32) NOT NULL,

    status ENUM('valid','revoked') DEFAULT 'valid',
    revoked_at DATETIME NULL
);

DELIMITER $$

CREATE TRIGGER prevent_illegal_updates
BEFORE UPDATE ON archived_certificates
FOR EACH ROW
BEGIN
    -- allow updating only:
    --   status
    --   revoked_at
    
    -- forbid changing any field other than status and revoked_at
    IF NEW.serial_number <> OLD.serial_number
       OR NEW.uid <> OLD.uid
       OR NEW.issue_time <> OLD.issue_time
       OR NEW.certificate_pem <> OLD.certificate_pem
       OR NEW.public_key_pem <> OLD.public_key_pem
       OR NEW.private_key_cipher <> OLD.private_key_cipher
       OR NEW.enc_algo <> OLD.enc_algo
       OR NEW.enc_nonce <> OLD.enc_nonce
       OR NEW.enc_tag <> OLD.enc_tag
    THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Immutable certificate fields cannot be modified';
    END IF;
END$$

DELIMITER ;

-- ----------------------------
-- 2. User DB Backup
-- ----------------------------
USE userdb_backup_db;

CREATE TABLE IF NOT EXISTS user_snapshots (
    snapshot_id BIGINT AUTO_INCREMENT PRIMARY KEY, -- automatically backup userdb whenever there's an update in userdb
    snapshot_ts DATETIME NOT NULL, -- timestamp when the backup snapshot occurred, because the automatic backup must be trackable over time

    uid VARCHAR(32) NOT NULL, -- unique user identifier of length up to 32 characters (only lowercase letters and digits)
    lastname VARCHAR(255) NOT NULL,
    firstname VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    pwd_hash VARCHAR(255) NOT NULL -- hashed password of the user
);

CREATE INDEX idx_snapshot_uid ON user_snapshots(uid); -- index on uid for faster lookups
CREATE INDEX idx_snapshot_ts ON user_snapshots(snapshot_ts); -- index on snapshot_ts for faster lookups

-- ----------------------------
-- 3. Log & Configuration Backup
-- ----------------------------
USE log_backup_db; -- use the log backup database for storing logs and config_backups tables

-- table for storing logs, named 'logs'
CREATE TABLE IF NOT EXISTS logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    source ENUM('web','auth','ca','backup','system') NOT NULL,
    level ENUM('DEBUG','INFO','WARN','ERROR') NOT NULL,
    timestamp DATETIME NOT NULL,
    message TEXT NOT NULL
);

-- table for storing configuration file backups, named 'config_backups'
CREATE TABLE IF NOT EXISTS config_backups (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    source ENUM('web','auth','ca','backup') NOT NULL,
    timestamp DATETIME NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    content MEDIUMTEXT NOT NULL
);
