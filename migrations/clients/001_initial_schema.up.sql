-- Migration: Initial schema for mobius-clients database
-- Description: Client registry, configurations, groups, and tags

-- Clients table
CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname VARCHAR(255) NOT NULL,
    os_type VARCHAR(50) NOT NULL,
    os_version VARCHAR(100),
    architecture VARCHAR(50),
    ip_address INET,
    mac_address MACADDR,
    headscale_node_id VARCHAR(255),
    last_seen TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(hostname)
);

-- Client configurations
CREATE TABLE IF NOT EXISTS client_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    config_key VARCHAR(255) NOT NULL,
    config_value TEXT,
    config_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(client_id, config_key)
);

-- Client tags
CREATE TABLE IF NOT EXISTS client_tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    tag_name VARCHAR(100) NOT NULL,
    tag_value VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(client_id, tag_name)
);

-- Client groups
CREATE TABLE IF NOT EXISTS client_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Client group memberships
CREATE TABLE IF NOT EXISTS client_group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID REFERENCES clients(id) ON DELETE CASCADE,
    group_id UUID REFERENCES client_groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(client_id, group_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_clients_hostname ON clients(hostname);
CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);
CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_clients_headscale_node_id ON clients(headscale_node_id);
CREATE INDEX IF NOT EXISTS idx_client_configurations_client_id ON client_configurations(client_id);
CREATE INDEX IF NOT EXISTS idx_client_tags_client_id ON client_tags(client_id);
CREATE INDEX IF NOT EXISTS idx_client_group_members_client_id ON client_group_members(client_id);
CREATE INDEX IF NOT EXISTS idx_client_group_members_group_id ON client_group_members(group_id);

-- Trigger to update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_client_configurations_updated_at BEFORE UPDATE ON client_configurations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_client_groups_updated_at BEFORE UPDATE ON client_groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
