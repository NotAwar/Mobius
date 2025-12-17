-- Seed data for mobius-app database

-- Insert test users
INSERT INTO users (username, email) VALUES
    ('admin', 'admin@mobius.local'),
    ('testuser', 'test@mobius.local')
ON CONFLICT (username) DO NOTHING;

-- Insert user preferences for the admin user
INSERT INTO user_preferences (user_id, theme, refresh_interval, auto_refresh, notifications_enabled)
SELECT id, 'dark', 5000, true, true
FROM users WHERE username = 'admin'
ON CONFLICT (user_id) DO NOTHING;

-- Display inserted data
SELECT 'Users created:' as status;
SELECT username, email, created_at FROM users;

SELECT 'Preferences created:' as status;
SELECT u.username, up.theme, up.refresh_interval, up.auto_refresh
FROM user_preferences up
JOIN users u ON up.user_id = u.id;
