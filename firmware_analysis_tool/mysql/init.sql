CREATE DATABASE IF NOT EXISTS firmware_info;

USE firmware_info;

CREATE TABLE IF NOT EXISTS firmware_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    firmware_hash VARCHAR(64) NOT NULL,
    firmware_name VARCHAR(255) NOT NULL,
    architecture VARCHAR(50),
    filesystem VARCHAR(50),
    operating_system VARCHAR(50),
    UNIQUE(firmware_hash, firmware_name)
);

CREATE TABLE IF NOT EXISTS fuzzy_hashes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    firmware_id INT NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_hash VARCHAR(255) NOT NULL,
    ssdeep_hash TEXT NOT NULL,
    sdhash_hash TEXT NOT NULL,
    FOREIGN KEY (firmware_id) REFERENCES firmware_info(id),
    UNIQUE (firmware_id, file_hash)
);