-- Mobius Clients Database Schema
-- Database: mobius_clients
-- Purpose: Client device management, configurations, and check-ins

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Clients table
CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255) NOT NULL,
    os_type VARCHAR(50) NOT NULL, -- darwin, linux, windows
    os_version VARCHAR(100),
    agent_version VARCHAR(50),
    ip_address INET,
    mac_address VARCHAR(17),
    status VARCHAR(20) NOT NULL DEFAULT 'offline', -- online, offline, inactive
    last_seen TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Client tags table (many-to-many relationship)
CREATE TABLE IF NOT EXISTS client_tags (
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    tag VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (client_id, tag)
);

-- Client groups table
CREATE TABLE IF NOT EXISTS client_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Client group memberships
CREATE TABLE IF NOT EXISTS client_group_memberships (
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES client_groups(id) ON DELETE CASCADE,
    joined_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (client_id, group_id)
);

-- Client configurations table
CREATE TABLE IF NOT EXISTS client_configurations (
    client_id UUID PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    check_in_interval INTEGER DEFAULT 300, -- seconds
    osquery_enabled BOOLEAN DEFAULT true,
    osquery_config JSONB DEFAULT '{}'::jsonb,
    custom_config JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Client check-ins table (for tracking connectivity)
CREATE TABLE IF NOT EXISTS client_check_ins (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    ip_address INET,
    agent_version VARCHAR(50),
    status VARCHAR(20),
    metadata JSONB DEFAULT '{}'::jsonb,
    checked_in_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Client hardware information
CREATE TABLE IF NOT EXISTS client_hardware (
    client_id UUID PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    cpu_model VARCHAR(255),
    cpu_cores INTEGER,
    memory_mb BIGINT,
    disk_gb BIGINT,
    gpu_model VARCHAR(255),
    hardware_info JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Client software inventory
CREATE TABLE IF NOT EXISTS client_software (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    vendor VARCHAR(255),
    install_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_clients_hostname ON clients(hostname);
CREATE INDEX IF NOT EXISTS idx_clients_os_type ON clients(os_type);
CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);
CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen);
CREATE INDEX IF NOT EXISTS idx_client_tags_client_id ON client_tags(client_id);
CREATE INDEX IF NOT EXISTS idx_client_tags_tag ON client_tags(tag);
CREATE INDEX IF NOT EXISTS idx_client_group_memberships_client_id ON client_group_memberships(client_id);
CREATE INDEX IF NOT EXISTS idx_client_group_memberships_group_id ON client_group_memberships(group_id);
CREATE INDEX IF NOT EXISTS idx_client_check_ins_client_id ON client_check_ins(client_id);
CREATE INDEX IF NOT EXISTS idx_client_check_ins_checked_in_at ON client_check_ins(checked_in_at);
CREATE INDEX IF NOT EXISTS idx_client_software_client_id ON client_software(client_id);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_client_groups_updated_at BEFORE UPDATE ON client_groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_client_configurations_updated_at BEFORE UPDATE ON client_configurations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_client_hardware_updated_at BEFORE UPDATE ON client_hardware
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_client_software_updated_at BEFORE UPDATE ON client_software
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to update last_seen on check-in
CREATE OR REPLACE FUNCTION update_client_last_seen()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE clients 
    SET last_seen = NEW.checked_in_at,
        status = COALESCE(NEW.status, 'online')
    WHERE id = NEW.client_id;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_last_seen_on_check_in AFTER INSERT ON client_check_ins
    FOR EACH ROW EXECUTE FUNCTION update_client_last_seen();

-- Insert default client groups
INSERT INTO client_groups (name, description) VALUES
    ('production', 'Production environment clients'),
    ('development', 'Development environment clients'),
    ('staging', 'Staging environment clients'),
    ('office', 'Office workstation clients'),
    ('remote', 'Remote worker clients')
ON CONFLICT (name) DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
