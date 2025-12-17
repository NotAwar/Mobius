-- Seed data for mobius-osquery database

-- Insert sample queries
INSERT INTO osquery_queries (name, query, interval, description, enabled) VALUES
    ('system_info', 'SELECT * FROM system_info;', 3600, 'Collect basic system information', true),
    ('listening_ports', 'SELECT * FROM listening_ports;', 300, 'Monitor open ports', true),
    ('users', 'SELECT * FROM users;', 1800, 'List system users', true),
    ('processes', 'SELECT name, pid, uid, cmdline FROM processes;', 60, 'Active processes', true)
ON CONFLICT (name) DO NOTHING;

-- Insert sample pack
INSERT INTO osquery_packs (name, description, enabled) VALUES
    ('security_monitoring', 'Security-focused queries', true),
    ('performance_monitoring', 'Performance metrics', true)
ON CONFLICT (name) DO NOTHING;

-- Link queries to packs
INSERT INTO osquery_pack_queries (pack_id, query_id, interval)
SELECT p.id, q.id, q.interval
FROM osquery_packs p
CROSS JOIN osquery_queries q
WHERE p.name = 'security_monitoring' AND q.name IN ('listening_ports', 'users')
ON CONFLICT (pack_id, query_id) DO NOTHING;

-- Display inserted data
SELECT 'Queries created:' as status;
SELECT name, interval, enabled FROM osquery_queries;

SELECT 'Packs created:' as status;
SELECT name, description, enabled FROM osquery_packs;
