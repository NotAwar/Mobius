-- Rollback for initial schema migration
-- Version: 001

-- Drop views
DROP VIEW IF EXISTS v_policies_summary;
DROP VIEW IF EXISTS v_devices_summary;

-- Drop triggers
DROP TRIGGER IF EXISTS update_licenses_timestamp;
DROP TRIGGER IF EXISTS update_applications_timestamp;
DROP TRIGGER IF EXISTS update_policies_timestamp;
DROP TRIGGER IF EXISTS update_device_groups_timestamp;
DROP TRIGGER IF EXISTS update_devices_timestamp;
DROP TRIGGER IF EXISTS update_users_timestamp;

-- Drop audit log
DROP TABLE IF EXISTS audit_log;

-- Drop system config
DROP TABLE IF EXISTS system_config;

-- Drop OSQuery tables
DROP TABLE IF EXISTS osquery_results;
DROP TABLE IF EXISTS osquery_queries;

-- Drop command tables
DROP TABLE IF EXISTS device_commands;

-- Drop application tables
DROP TABLE IF EXISTS app_group_assignments;
DROP TABLE IF EXISTS app_device_assignments;
DROP TABLE IF EXISTS applications;

-- Drop policy tables
DROP TABLE IF EXISTS policy_group_assignments;
DROP TABLE IF EXISTS policy_device_assignments;
DROP TABLE IF EXISTS policies;

-- Drop device group tables
DROP TABLE IF EXISTS device_group_memberships;
DROP TABLE IF EXISTS device_groups;

-- Drop device tables
DROP TABLE IF EXISTS device_tokens;
DROP TABLE IF EXISTS devices;

-- Drop license tables
DROP TABLE IF EXISTS license_audit;
DROP TABLE IF EXISTS licenses;

-- Drop auth tables
DROP TABLE IF EXISTS auth_tokens;
DROP TABLE IF EXISTS users;

-- Drop migration tracking
DROP TABLE IF EXISTS schema_migrations;
