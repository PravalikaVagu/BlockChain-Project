-- Create the database (execute this manually in MySQL if it doesn't exist)
CREATE DATABASE IF NOT EXISTS finalsupply; -- Added IF NOT EXISTS for safety

-- Use the database
USE finalsupply;

-- Create Users Table
CREATE TABLE IF NOT EXISTS Users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL, -- In a real app, hash passwords!
    role ENUM('Admin', 'Producer', 'Consumer') NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL -- Corrected syntax: NOT NULL should be at the end
);

-- Insert some initial users for testing (passwords are plain text for simplicity)
INSERT IGNORE INTO Users (username, password, role) VALUES ('admin', 'adminpass', 'Admin');
INSERT IGNORE INTO Users (username, password, role) VALUES ('producer1', 'prodpass', 'Producer');
INSERT IGNORE INTO Users (username, password, role) VALUES ('consumer1', 'conspass', 'Consumer');

-- Create Products Table
CREATE TABLE IF NOT EXISTS Products (
    product_id INT AUTO_INCREMENT PRIMARY KEY,
    food_item_id VARCHAR(255) UNIQUE NOT NULL, -- Unique identifier for the product batch
    product_name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL DEFAULT 0.00, -- Price of the product
    producer_username VARCHAR(255) NOT NULL, -- Who added this product
    hash_code VARCHAR(256) NOT NULL,         -- SHA256 hash of core product data
    verification_status ENUM('Pending', 'Verified', 'Tampered') DEFAULT 'Pending',
    verified_by VARCHAR(255),                -- Admin who verified
    verified_at TIMESTAMP NULL,              -- When it was verified
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (producer_username) REFERENCES Users(username) ON DELETE CASCADE
);

-- Create SupplyChainEvents Table
CREATE TABLE IF NOT EXISTS SupplyChainEvents (
    event_id INT AUTO_INCREMENT PRIMARY KEY,
    food_item_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL, -- e.g., 'Harvested', 'Shipped', 'Received', 'Processed'
    location VARCHAR(255) NOT NULL,
    event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT,                     -- Additional details for the event
    FOREIGN KEY (food_item_id) REFERENCES Products(food_item_id) ON DELETE CASCADE
);

-- Table for Orders
CREATE TABLE IF NOT EXISTS Orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_amount DECIMAL(10, 2) NOT NULL,
    shipping_address_line1 VARCHAR(255) NOT NULL,
    shipping_address_line2 VARCHAR(255),
    shipping_city VARCHAR(100) NOT NULL,
    shipping_state VARCHAR(100) NOT NULL,
    shipping_zip_code VARCHAR(20) NOT NULL,
    shipping_country VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'Pending', -- e.g., 'Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled'
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
);

-- Table for Order Details (items within each order)
CREATE TABLE IF NOT EXISTS OrderDetails (
    order_detail_id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    product_id INT NOT NULL, -- Links to Products table's product_id
    quantity INT NOT NULL,
    price_at_order DECIMAL(10, 2) NOT NULL, -- Price of the product when the order was placed
    FOREIGN KEY (order_id) REFERENCES Orders(order_id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES Products(product_id) ON DELETE CASCADE
);

-- Table for User Shipping Addresses
CREATE TABLE IF NOT EXISTS UserAddresses (
    address_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    address_name VARCHAR(255), -- e.g., "Home", "Work"
    address_line1 VARCHAR(255) NOT NULL,
    address_line2 VARCHAR(255),
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100) NOT NULL,
    zip_code VARCHAR(20) NOT NULL,
    country VARCHAR(100) NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
);
