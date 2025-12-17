-- Migration: 005_enrollment_keys_table
-- Description: Creates enrollment_keys table for client onboarding
-- Database: clients
-- Created: 2025-12-18

-- Enrollment keys table
CREATE TABLE IF NOT EXISTS enrollment_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    key TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by UUID, -- References users table in app database
    expires_at TIMESTAMP,
    max_uses INTEGER DEFAULT 1,
    used_count INTEGER DEFAULT 0,
    revoked BOOLEAN DEFAULT FALSE,
    tags TEXT[],
    auto_assign_group_ids UUID[],
    metadata JSONB
);

-- Indexes for enrollment keys
CREATE INDEX IF NOT EXISTS idx_enrollment_keys_key ON enrollment_keys(key);
CREATE INDEX IF NOT EXISTS idx_enrollment_keys_expires ON enrollment_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_enrollment_keys_revoked ON enrollment_keys(revoked);
CREATE INDEX IF NOT EXISTS idx_enrollment_keys_created ON enrollment_keys(created_at);

-- Client check-ins table (if not exists from previous migration)
CREATE TABLE IF NOT EXISTS client_check_ins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    ip_address INET,
    status TEXT NOT NULL DEFAULT 'success',
    system_info JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for check-ins
CREATE INDEX IF NOT EXISTS idx_client_check_ins_client ON client_check_ins(client_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_client_check_ins_timestamp ON client_check_ins(timestamp DESC);

-- Add client_key column to clients table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'clients' AND column_name = 'client_key') THEN
        ALTER TABLE clients ADD COLUMN client_key TEXT;
        CREATE UNIQUE INDEX idx_clients_key ON clients(client_key);
    END IF;
END $$;

-- Add enrollment_method column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'clients' AND column_name = 'enrollment_method') THEN
        ALTER TABLE clients ADD COLUMN enrollment_method TEXT DEFAULT 'manual';
    END IF;
END $$;

-- Comments
COMMENT ON TABLE enrollment_keys IS 'Enrollment keys for client onboarding';
COMMENT ON COLUMN enrollment_keys.key IS 'Base64-encoded random key (32 bytes)';
COMMENT ON COLUMN enrollment_keys.max_uses IS '0 means unlimited';
COMMENT ON COLUMN enrollment_keys.auto_assign_group_ids IS 'Groups to auto-assign on enrollment';

COMMENT ON TABLE client_check_ins IS 'Client check-in history';
COMMENT ON COLUMN client_check_ins.status IS 'success, failed, degraded';
