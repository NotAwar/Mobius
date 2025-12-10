-- Mobius MDM Database Schema
-- Version: 001
-- Description: Initial schema for persistent storage

-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- =============================================================================
-- USERS & AUTHENTICATION
-- =============================================================================

-- Users table for admin and operator accounts
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL, -- bcrypt hashed password
    role TEXT NOT NULL CHECK(role IN ('admin', 'operator', 'viewer')),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT 1
);

-- Authentication tokens (JWT storage for revocation)
CREATE TABLE IF NOT EXISTS auth_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL, -- SHA256 hash of JWT token
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    is_revoked BOOLEAN NOT NULL DEFAULT 0,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for token lookup and cleanup
CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id ON auth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires_at ON auth_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_token_hash ON auth_tokens(token_hash);

-- =============================================================================
-- LICENSING
-- =============================================================================

-- License information
CREATE TABLE IF NOT EXISTS licenses (
    id TEXT PRIMARY KEY,
    license_key TEXT UNIQUE NOT NULL,
    tier TEXT NOT NULL CHECK(tier IN ('community', 'professional', 'enterprise')),
    device_limit INTEGER NOT NULL,
    features TEXT NOT NULL, -- JSON array of feature strings
    issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP, -- NULL for perpetual licenses
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- License audit log
CREATE TABLE IF NOT EXISTS license_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT NOT NULL,
    action TEXT NOT NULL, -- 'activated', 'deactivated', 'updated', 'expired'
    details TEXT, -- JSON details
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_license_audit_license_id ON license_audit(license_id);

-- =============================================================================
-- DEVICES
-- =============================================================================

-- Device registry
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    uuid TEXT UNIQUE NOT NULL,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL CHECK(platform IN ('windows', 'macos', 'linux', 'ios', 'android')),
    os_version TEXT NOT NULL,
    serial_number TEXT,
    hardware_info TEXT, -- JSON object with hardware details
    labels TEXT, -- JSON object for key-value labels
    enrollment_secret TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'offline' CHECK(status IN ('online', 'offline', 'pending')),
    enrolled_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP, -- Soft delete
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common device queries
CREATE INDEX IF NOT EXISTS idx_devices_uuid ON devices(uuid);
CREATE INDEX IF NOT EXISTS idx_devices_platform ON devices(platform);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_deleted_at ON devices(deleted_at);

-- Device authentication tokens
CREATE TABLE IF NOT EXISTS device_tokens (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    token_hash TEXT NOT NULL, -- SHA256 hash of device token
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    is_revoked BOOLEAN NOT NULL DEFAULT 0,
    
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_device_tokens_device_id ON device_tokens(device_id);
CREATE INDEX IF NOT EXISTS idx_device_tokens_token_hash ON device_tokens(token_hash);

-- =============================================================================
-- DEVICE GROUPS
-- =============================================================================

-- Device groups for organization
CREATE TABLE IF NOT EXISTS device_groups (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    filters TEXT, -- JSON object for auto-assignment filters
    labels TEXT, -- JSON object for group metadata
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Many-to-many: devices to groups
CREATE TABLE IF NOT EXISTS device_group_memberships (
    device_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (device_id, group_id),
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES device_groups(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_group_memberships_group_id ON device_group_memberships(group_id);
CREATE INDEX IF NOT EXISTS idx_group_memberships_device_id ON device_group_memberships(device_id);

-- =============================================================================
-- POLICIES
-- =============================================================================

-- Policy definitions
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    platform TEXT NOT NULL CHECK(platform IN ('windows', 'macos', 'linux', 'ios', 'android', 'all')),
    configuration TEXT NOT NULL, -- JSON configuration object
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_policies_platform ON policies(platform);
CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);

-- Policy assignments to devices
CREATE TABLE IF NOT EXISTS policy_device_assignments (
    policy_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (policy_id, device_id),
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_policy_device_policy_id ON policy_device_assignments(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_device_device_id ON policy_device_assignments(device_id);

-- Policy assignments to groups
CREATE TABLE IF NOT EXISTS policy_group_assignments (
    policy_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (policy_id, group_id),
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES device_groups(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_policy_group_policy_id ON policy_group_assignments(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_group_group_id ON policy_group_assignments(group_id);

-- =============================================================================
-- APPLICATIONS
-- =============================================================================

-- Application packages
CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    platform TEXT NOT NULL CHECK(platform IN ('windows', 'macos', 'linux', 'ios', 'android')),
    size INTEGER NOT NULL,
    checksum TEXT NOT NULL, -- SHA256 checksum
    package_data BLOB, -- Binary package data (consider file storage for large apps)
    package_path TEXT, -- Alternative: file system path
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(name, version, platform)
);

CREATE INDEX IF NOT EXISTS idx_applications_platform ON applications(platform);
CREATE INDEX IF NOT EXISTS idx_applications_name ON applications(name);

-- Application assignments to devices
CREATE TABLE IF NOT EXISTS app_device_assignments (
    app_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    installation_status TEXT NOT NULL DEFAULT 'pending' CHECK(installation_status IN ('pending', 'downloading', 'installing', 'installed', 'failed', 'removed')),
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    installed_at TIMESTAMP,
    error_message TEXT,
    
    PRIMARY KEY (app_id, device_id),
    FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_device_app_id ON app_device_assignments(app_id);
CREATE INDEX IF NOT EXISTS idx_app_device_device_id ON app_device_assignments(device_id);
CREATE INDEX IF NOT EXISTS idx_app_device_status ON app_device_assignments(installation_status);

-- Application assignments to groups
CREATE TABLE IF NOT EXISTS app_group_assignments (
    app_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (app_id, group_id),
    FOREIGN KEY (app_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES device_groups(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_app_group_app_id ON app_group_assignments(app_id);
CREATE INDEX IF NOT EXISTS idx_app_group_group_id ON app_group_assignments(group_id);

-- =============================================================================
-- DEVICE COMMANDS & QUEUE
-- =============================================================================

-- Command queue for device management
CREATE TABLE IF NOT EXISTS device_commands (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    command TEXT NOT NULL, -- Command name/type
    parameters TEXT, -- JSON parameters
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'in-progress', 'completed', 'failed', 'timeout', 'cancelled')),
    result TEXT, -- JSON result data
    error_message TEXT,
    timeout_minutes INTEGER NOT NULL DEFAULT 5, -- Configurable timeout
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL, -- Computed: created_at + timeout_minutes
    
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_commands_device_id ON device_commands(device_id);
CREATE INDEX IF NOT EXISTS idx_commands_status ON device_commands(status);
CREATE INDEX IF NOT EXISTS idx_commands_expires_at ON device_commands(expires_at);
CREATE INDEX IF NOT EXISTS idx_commands_created_at ON device_commands(created_at);

-- =============================================================================
-- OSQUERY
-- =============================================================================

-- OSQuery queries
CREATE TABLE IF NOT EXISTS osquery_queries (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    query TEXT NOT NULL,
    description TEXT,
    platforms TEXT NOT NULL, -- JSON array of supported platforms
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- OSQuery results from devices
CREATE TABLE IF NOT EXISTS osquery_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    query_id TEXT,
    query TEXT NOT NULL, -- Actual SQL query executed
    columns TEXT NOT NULL, -- JSON array of column names
    rows TEXT NOT NULL, -- JSON array of result rows
    duration_ms INTEGER NOT NULL,
    error_message TEXT,
    executed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (query_id) REFERENCES osquery_queries(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_osquery_results_device_id ON osquery_results(device_id);
CREATE INDEX IF NOT EXISTS idx_osquery_results_query_id ON osquery_results(query_id);
CREATE INDEX IF NOT EXISTS idx_osquery_results_executed_at ON osquery_results(executed_at);

-- =============================================================================
-- CONFIGURATION & SETTINGS
-- =============================================================================

-- System configuration
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL, -- JSON value
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Insert default configuration
INSERT INTO system_config (key, value, description) VALUES
    ('jwt_expiry_minutes', '15', 'JWT access token expiry in minutes (configurable)'),
    ('jwt_refresh_days', '7', 'JWT refresh token expiry in days'),
    ('command_timeout_default', '5', 'Default command timeout in minutes'),
    ('command_timeout_max', '60', 'Maximum command timeout in minutes'),
    ('backup_enabled', 'true', 'Enable automatic database backups'),
    ('backup_schedule', '0 2 * * *', 'Backup schedule in cron format (2 AM daily)'),
    ('cleanup_enabled', 'true', 'Enable automatic data cleanup'),
    ('cleanup_commands_days', '30', 'Delete command results older than N days'),
    ('cleanup_osquery_days', '90', 'Delete OSQuery results older than N days'),
    ('cleanup_tokens_hours', '24', 'Delete expired tokens after N hours'),
    ('cleanup_deleted_devices_days', '7', 'Purge soft-deleted devices after N days')
ON CONFLICT(key) DO NOTHING;

-- =============================================================================
-- AUDIT LOG
-- =============================================================================

-- Audit trail for important actions
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    device_id TEXT,
    action TEXT NOT NULL, -- 'device.enroll', 'policy.assign', 'user.login', etc.
    resource_type TEXT NOT NULL, -- 'device', 'policy', 'application', etc.
    resource_id TEXT,
    details TEXT, -- JSON details
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_device_id ON audit_log(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- =============================================================================
-- TRIGGERS FOR UPDATED_AT
-- =============================================================================

-- Auto-update updated_at timestamps
CREATE TRIGGER IF NOT EXISTS update_users_timestamp 
    AFTER UPDATE ON users
    FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_devices_timestamp 
    AFTER UPDATE ON devices
    FOR EACH ROW
BEGIN
    UPDATE devices SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_device_groups_timestamp 
    AFTER UPDATE ON device_groups
    FOR EACH ROW
BEGIN
    UPDATE device_groups SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_policies_timestamp 
    AFTER UPDATE ON policies
    FOR EACH ROW
BEGIN
    UPDATE policies SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_applications_timestamp 
    AFTER UPDATE ON applications
    FOR EACH ROW
BEGIN
    UPDATE applications SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_licenses_timestamp 
    AFTER UPDATE ON licenses
    FOR EACH ROW
BEGIN
    UPDATE licenses SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- =============================================================================
-- VIEWS FOR COMMON QUERIES
-- =============================================================================

-- Enrolled devices with group count
CREATE VIEW IF NOT EXISTS v_devices_summary AS
SELECT 
    d.id,
    d.uuid,
    d.hostname,
    d.platform,
    d.os_version,
    d.status,
    d.enrolled_at,
    d.last_seen,
    COUNT(DISTINCT dgm.group_id) as group_count,
    COUNT(DISTINCT pda.policy_id) as policy_count
FROM devices d
LEFT JOIN device_group_memberships dgm ON d.id = dgm.device_id
LEFT JOIN policy_device_assignments pda ON d.id = pda.device_id
WHERE d.deleted_at IS NULL
GROUP BY d.id;

-- Active policies with assignment counts
CREATE VIEW IF NOT EXISTS v_policies_summary AS
SELECT 
    p.id,
    p.name,
    p.platform,
    p.enabled,
    COUNT(DISTINCT pda.device_id) as device_count,
    COUNT(DISTINCT pga.group_id) as group_count
FROM policies p
LEFT JOIN policy_device_assignments pda ON p.id = pda.policy_id
LEFT JOIN policy_group_assignments pga ON p.id = pga.policy_id
GROUP BY p.id;

-- Database version tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_migrations (version) VALUES (1);
