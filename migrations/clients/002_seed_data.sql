-- Seed data for mobius-clients database

-- Insert sample clients
INSERT INTO clients (hostname, os_type, os_version, ip_address, last_seen) VALUES
    ('macbook-pro-01', 'darwin', '14.2.1', '192.168.1.100', NOW()),
    ('ubuntu-server-01', 'linux', '22.04', '192.168.1.101', NOW() - INTERVAL '5 minutes'),
    ('windows-desktop-01', 'windows', '11', '192.168.1.102', NOW() - INTERVAL '10 minutes')
ON CONFLICT (hostname) DO NOTHING;

-- Insert configuration for clients
INSERT INTO client_configurations (client_id, osquery_interval, osquery_config)
SELECT id, 60, '{"options": {"verbose": true}}'::jsonb
FROM clients
WHERE hostname IN ('macbook-pro-01', 'ubuntu-server-01', 'windows-desktop-01')
ON CONFLICT (client_id) DO NOTHING;

-- Insert tags
INSERT INTO client_tags (name, color) VALUES
    ('production', '#22c55e'),
    ('development', '#3b82f6'),
    ('staging', '#f59e0b')
ON CONFLICT (name) DO NOTHING;

-- Insert client groups
INSERT INTO client_groups (name, description) VALUES
    ('Servers', 'All server machines'),
    ('Workstations', 'Developer workstations'),
    ('Production', 'Production environment')
ON CONFLICT (name) DO NOTHING;

-- Display inserted data
SELECT 'Clients created:' as status;
SELECT hostname, os_type, ip_address, status FROM clients;
