-- Mobius Audit Database Schema
-- Database: mobius_audit
-- Purpose: Comprehensive audit logging for compliance and security monitoring

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Audit logs table (main audit trail)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id UUID, -- NULL for system actions
    username VARCHAR(255), -- Denormalized for performance
    action VARCHAR(100) NOT NULL, -- CREATE, READ, UPDATE, DELETE, LOGIN, LOGOUT, etc.
    resource_type VARCHAR(100) NOT NULL, -- user, client, query, pack, role, etc.
    resource_id VARCHAR(255), -- UUID or identifier of the resource
    resource_name VARCHAR(255), -- Denormalized resource name
    status VARCHAR(20) NOT NULL, -- success, failure, partial
    ip_address INET,
    user_agent TEXT,
    request_method VARCHAR(10), -- GET, POST, PUT, DELETE
    request_path TEXT,
    changes JSONB DEFAULT '{}'::jsonb, -- Before/after values for UPDATE
    metadata JSONB DEFAULT '{}'::jsonb, -- Additional context
    error_message TEXT,
    duration_ms INTEGER
);

-- Audit sources table (track different audit sources)
CREATE TABLE IF NOT EXISTS audit_sources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    type VARCHAR(50) NOT NULL, -- api, cli, agent, system, external
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    config JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Audit events configuration (define which events to audit)
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) UNIQUE NOT NULL,
    category VARCHAR(50) NOT NULL, -- authentication, authorization, data, system, security
    severity VARCHAR(20) DEFAULT 'info', -- debug, info, warning, error, critical
    enabled BOOLEAN DEFAULT true,
    retention_days INTEGER DEFAULT 90,
    alert_on_failure BOOLEAN DEFAULT false,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_id ON audit_logs(resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON audit_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_sources_name ON audit_sources(name);
CREATE INDEX IF NOT EXISTS idx_audit_sources_type ON audit_sources(type);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_category ON audit_events(category);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_audit_sources_updated_at BEFORE UPDATE ON audit_sources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_audit_events_updated_at BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default audit sources
INSERT INTO audit_sources (name, type, description) VALUES
    ('api_server', 'api', 'Main API server audit logs'),
    ('cli_client', 'cli', 'Command-line client actions'),
    ('agent', 'agent', 'Client agent actions'),
    ('system', 'system', 'System-level actions'),
    ('keycloak', 'external', 'Keycloak authentication events')
ON CONFLICT (name) DO NOTHING;

-- Insert default audit event configurations
INSERT INTO audit_events (event_type, category, severity, enabled, retention_days, alert_on_failure, description) VALUES
    -- Authentication events
    ('user.login.success', 'authentication', 'info', true, 365, false, 'Successful user login'),
    ('user.login.failure', 'authentication', 'warning', true, 365, true, 'Failed login attempt'),
    ('user.logout', 'authentication', 'info', true, 90, false, 'User logout'),
    ('user.session.expired', 'authentication', 'info', true, 90, false, 'User session expired'),
    ('user.password.changed', 'authentication', 'info', true, 365, false, 'User password changed'),
    
    -- Authorization events
    ('access.denied', 'authorization', 'warning', true, 365, true, 'Access denied to resource'),
    ('permission.granted', 'authorization', 'info', true, 180, false, 'Permission granted'),
    ('permission.revoked', 'authorization', 'info', true, 180, false, 'Permission revoked'),
    ('role.assigned', 'authorization', 'info', true, 365, false, 'Role assigned to user'),
    ('role.removed', 'authorization', 'info', true, 365, false, 'Role removed from user'),
    
    -- Data events
    ('user.created', 'data', 'info', true, 365, false, 'User account created'),
    ('user.updated', 'data', 'info', true, 180, false, 'User account updated'),
    ('user.deleted', 'data', 'warning', true, 730, false, 'User account deleted'),
    ('client.registered', 'data', 'info', true, 365, false, 'New client registered'),
    ('client.updated', 'data', 'info', true, 90, false, 'Client information updated'),
    ('client.decommissioned', 'data', 'info', true, 365, false, 'Client decommissioned'),
    ('query.created', 'data', 'info', true, 180, false, 'OSQuery query created'),
    ('query.executed', 'data', 'info', true, 30, false, 'OSQuery query executed'),
    ('query.deleted', 'data', 'info', true, 365, false, 'OSQuery query deleted'),
    ('pack.created', 'data', 'info', true, 180, false, 'OSQuery pack created'),
    ('pack.updated', 'data', 'info', true, 90, false, 'OSQuery pack updated'),
    ('pack.deleted', 'data', 'info', true, 365, false, 'OSQuery pack deleted'),
    
    -- System events
    ('server.started', 'system', 'info', true, 365, false, 'Server started'),
    ('server.stopped', 'system', 'info', true, 365, false, 'Server stopped'),
    ('database.connected', 'system', 'info', true, 90, false, 'Database connection established'),
    ('database.disconnected', 'system', 'warning', true, 365, false, 'Database disconnected'),
    ('migration.executed', 'system', 'info', true, 730, false, 'Database migration executed'),
    
    -- Security events
    ('api.key.created', 'security', 'info', true, 730, false, 'API key created'),
    ('api.key.revoked', 'security', 'warning', true, 730, false, 'API key revoked'),
    ('suspicious.activity', 'security', 'critical', true, 730, true, 'Suspicious activity detected'),
    ('brute.force.attempt', 'security', 'critical', true, 730, true, 'Brute force attempt detected'),
    ('config.changed', 'security', 'warning', true, 730, false, 'System configuration changed')
ON CONFLICT (event_type) DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
