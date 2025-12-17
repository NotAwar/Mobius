-- Mobius OSQuery Database Schema
-- Database: mobius_osquery
-- Purpose: OSQuery query management, packs, and results storage

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- OSQuery queries table
CREATE TABLE IF NOT EXISTS osquery_queries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    query TEXT NOT NULL,
    description TEXT,
    platform VARCHAR(50), -- darwin, linux, windows, all
    interval INTEGER DEFAULT 3600, -- seconds
    active BOOLEAN DEFAULT true,
    tags JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- OSQuery packs table
CREATE TABLE IF NOT EXISTS osquery_packs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    platform VARCHAR(50),
    active BOOLEAN DEFAULT true,
    tags JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Pack-Query associations (many-to-many)
CREATE TABLE IF NOT EXISTS osquery_pack_queries (
    pack_id UUID NOT NULL REFERENCES osquery_packs(id) ON DELETE CASCADE,
    query_id UUID NOT NULL REFERENCES osquery_queries(id) ON DELETE CASCADE,
    interval INTEGER, -- Override query interval for this pack
    snapshot BOOLEAN DEFAULT false,
    removed BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (pack_id, query_id)
);

-- OSQuery results table
CREATE TABLE IF NOT EXISTS osquery_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    query_id UUID NOT NULL REFERENCES osquery_queries(id) ON DELETE CASCADE,
    client_id UUID NOT NULL,
    executed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    success BOOLEAN NOT NULL,
    row_count INTEGER DEFAULT 0,
    results JSONB DEFAULT '[]'::jsonb,
    error TEXT,
    duration_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Partitioned results table for better performance (optional, for high-volume)
-- CREATE TABLE IF NOT EXISTS osquery_results_archive (
--     LIKE osquery_results INCLUDING ALL
-- ) PARTITION BY RANGE (created_at);

-- Query execution jobs (for tracking async executions)
CREATE TABLE IF NOT EXISTS osquery_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    query_id UUID NOT NULL REFERENCES osquery_queries(id) ON DELETE CASCADE,
    client_ids JSONB NOT NULL, -- Array of client UUIDs
    status VARCHAR(20) DEFAULT 'pending', -- pending, running, completed, failed
    total_clients INTEGER NOT NULL,
    completed_clients INTEGER DEFAULT 0,
    failed_clients INTEGER DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Query schedules (for recurring queries)
CREATE TABLE IF NOT EXISTS osquery_schedules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    query_id UUID NOT NULL REFERENCES osquery_queries(id) ON DELETE CASCADE,
    client_group_id UUID, -- Optional: target specific client group
    cron_expression VARCHAR(100), -- Cron format: "0 */6 * * *"
    interval INTEGER, -- Alternative to cron: interval in seconds
    enabled BOOLEAN DEFAULT true,
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_osquery_queries_name ON osquery_queries(name);
CREATE INDEX IF NOT EXISTS idx_osquery_queries_platform ON osquery_queries(platform);
CREATE INDEX IF NOT EXISTS idx_osquery_queries_active ON osquery_queries(active);
CREATE INDEX IF NOT EXISTS idx_osquery_packs_name ON osquery_packs(name);
CREATE INDEX IF NOT EXISTS idx_osquery_packs_active ON osquery_packs(active);
CREATE INDEX IF NOT EXISTS idx_osquery_pack_queries_pack_id ON osquery_pack_queries(pack_id);
CREATE INDEX IF NOT EXISTS idx_osquery_pack_queries_query_id ON osquery_pack_queries(query_id);
CREATE INDEX IF NOT EXISTS idx_osquery_results_query_id ON osquery_results(query_id);
CREATE INDEX IF NOT EXISTS idx_osquery_results_client_id ON osquery_results(client_id);
CREATE INDEX IF NOT EXISTS idx_osquery_results_executed_at ON osquery_results(executed_at);
CREATE INDEX IF NOT EXISTS idx_osquery_results_success ON osquery_results(success);
CREATE INDEX IF NOT EXISTS idx_osquery_jobs_query_id ON osquery_jobs(query_id);
CREATE INDEX IF NOT EXISTS idx_osquery_jobs_status ON osquery_jobs(status);
CREATE INDEX IF NOT EXISTS idx_osquery_schedules_query_id ON osquery_schedules(query_id);
CREATE INDEX IF NOT EXISTS idx_osquery_schedules_next_run_at ON osquery_schedules(next_run_at);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_osquery_queries_updated_at BEFORE UPDATE ON osquery_queries
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_osquery_packs_updated_at BEFORE UPDATE ON osquery_packs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_osquery_jobs_updated_at BEFORE UPDATE ON osquery_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_osquery_schedules_updated_at BEFORE UPDATE ON osquery_schedules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default queries
INSERT INTO osquery_queries (name, query, description, platform, interval, tags) VALUES
    ('system_info', 'SELECT * FROM system_info;', 'Get system information', 'all', 3600, '["system", "inventory"]'::jsonb),
    ('listening_ports', 'SELECT * FROM listening_ports WHERE port != 0;', 'Monitor listening network ports', 'all', 300, '["network", "security"]'::jsonb),
    ('running_processes', 'SELECT pid, name, path, cmdline FROM processes;', 'List all running processes', 'all', 60, '["processes", "monitoring"]'::jsonb),
    ('user_accounts', 'SELECT * FROM users;', 'List all user accounts', 'all', 3600, '["users", "security"]'::jsonb),
    ('installed_applications_macos', 'SELECT * FROM apps;', 'List installed applications on macOS', 'darwin', 86400, '["applications", "inventory", "macos"]'::jsonb),
    ('installed_programs_windows', 'SELECT * FROM programs;', 'List installed programs on Windows', 'windows', 86400, '["applications", "inventory", "windows"]'::jsonb),
    ('kernel_modules_linux', 'SELECT * FROM kernel_modules;', 'List loaded kernel modules on Linux', 'linux', 3600, '["kernel", "security", "linux"]'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Insert default packs
INSERT INTO osquery_packs (name, description, platform, tags) VALUES
    ('security_monitoring', 'Security-focused queries', 'all', '["security", "compliance"]'::jsonb),
    ('performance_monitoring', 'Performance and resource monitoring', 'all', '["performance", "monitoring"]'::jsonb),
    ('inventory', 'Hardware and software inventory', 'all', '["inventory", "compliance"]'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Associate queries with packs
INSERT INTO osquery_pack_queries (pack_id, query_id, interval)
SELECT 
    (SELECT id FROM osquery_packs WHERE name = 'security_monitoring'),
    (SELECT id FROM osquery_queries WHERE name = 'listening_ports'),
    300
WHERE EXISTS (SELECT 1 FROM osquery_packs WHERE name = 'security_monitoring')
  AND EXISTS (SELECT 1 FROM osquery_queries WHERE name = 'listening_ports')
ON CONFLICT DO NOTHING;

INSERT INTO osquery_pack_queries (pack_id, query_id, interval)
SELECT 
    (SELECT id FROM osquery_packs WHERE name = 'performance_monitoring'),
    (SELECT id FROM osquery_queries WHERE name = 'running_processes'),
    60
WHERE EXISTS (SELECT 1 FROM osquery_packs WHERE name = 'performance_monitoring')
  AND EXISTS (SELECT 1 FROM osquery_queries WHERE name = 'running_processes')
ON CONFLICT DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
