-- database_setup.sql
-- This script sets up the database schema for the Zeus Customs API

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    api_quota INT NOT NULL DEFAULT 1000,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    api_key varchar(280) NULL,
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_username_key UNIQUE (username)
);

-- Create API lookup logs table
CREATE TABLE IF NOT EXISTS lookup_logs (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    lookup_type VARCHAR(20) NOT NULL,  -- 'single' or 'batch'
    house_bill VARCHAR(50),
    voc_scac VARCHAR(10),
    master_bill VARCHAR(50),
    status VARCHAR(20) NOT NULL,  -- 'success' or 'error'
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(50),
    user_agent TEXT,
    country VARCHAR(100),
    region VARCHAR(100),
    city VARCHAR(100),
    latitude FLOAT,
    longitude FLOAT
);

-- Create batch request logs
CREATE TABLE IF NOT EXISTS batch_requests (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    request_size INT NOT NULL,
    success_count INT NOT NULL,
    error_count INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create API usage stats
CREATE TABLE IF NOT EXISTS api_usage (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    endpoint VARCHAR(100) NOT NULL,
    request_count INT NOT NULL DEFAULT 1,
    date DATE NOT NULL,
    UNIQUE (user_id, endpoint, date),
    country VARCHAR(100),
    region VARCHAR(100),
    city VARCHAR(100),
    latitude FLOAT,
    longitude FLOAT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    ip_address VARCHAR(50),
    success BOOLEAN DEFAULT TRUE,
    message TEXT
);

-- Create ISF filings table (based on your existing schema)
CREATE TABLE IF NOT EXISTS isfs (
    id SERIAL PRIMARY KEY,
    manufacturer_name VARCHAR(255),
    seller_name VARCHAR(255),
    buyer_name VARCHAR(255),
    ship_to_name VARCHAR(255),
    container_stuffing_location VARCHAR(255),
    consolidator_name VARCHAR(255),
    importer_of_record VARCHAR(50),
    consignee_number VARCHAR(50),
    country_of_origin VARCHAR(50),
    tariff_or_hts_number VARCHAR(50),
    bill_of_lading_number VARCHAR(50),
    carrier_scac_code VARCHAR(10),
    estimated_time_of_arrival TIMESTAMP,
    estimated_time_of_departure TIMESTAMP,
    bill_type VARCHAR(20),
    reference_numbers JSONB,
    mode_of_transportation VARCHAR(50),
    voyage_number VARCHAR(50),
    vessel_name VARCHAR(100),
    isf_id VARCHAR(50) UNIQUE,
    bill_match_confirmation BOOLEAN DEFAULT FALSE,
    isf_acceptance_confirmation BOOLEAN DEFAULT FALSE,
    origin_country VARCHAR(50),
    destination_port VARCHAR(100),
    total_value DECIMAL(15, 2),
    currency_code VARCHAR(3),
    commodities JSONB,
    isf_pdf_url VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- Create HBL to MBL mapping table (for caching/historical purposes)
CREATE TABLE IF NOT EXISTS hbl_mbl_mappings (
    id SERIAL PRIMARY KEY,
    house_bill VARCHAR(50) NOT NULL,
    voc_scac VARCHAR(10) NOT NULL,
    master_bill VARCHAR(50) NOT NULL,
    first_lookup_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_lookup_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lookup_count INT NOT NULL DEFAULT 1,
    UNIQUE (house_bill, voc_scac)
);

CREATE TABLE IF NOT EXISTS access_tokens (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    token_id VARCHAR(36) UNIQUE NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    ip_address varchar(50) NULL,
    user_agent text NULL,
    country VARCHAR(100),
    region VARCHAR(100),
    city VARCHAR(100),
    latitude FLOAT,
    longitude FLOAT
);

CREATE TABLE IF NOT EXISTS notification_tracking (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    last_id INTEGER NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Insert demo users
INSERT INTO users (username, password_hash, email, role, api_quota)
VALUES 
    ('demo', '$2b$12$Dwt1DqB.XwDIWKGiKxHYxu.uc1uKHMrOh1QUltOLuh5vxN4r7VHxq', 'demo@cbpapi.com', 'user', 100),
    ('admin', '$2b$12$4Eo5Csfd.GbIYpUZM7CKaeP0jIFLiHBM2Bl1PCgR9ZYoMJ9YrNGtG', 'admin@cbpapi.com', 'admin', 1000)
ON CONFLICT (username) DO NOTHING;

