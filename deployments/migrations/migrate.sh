#!/bin/bash
# Mobius Database Migration Script
# Executes SQL migrations against PostgreSQL databases

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-postgres}"

# Migration tracking
MIGRATIONS_TABLE="schema_migrations"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check database connectivity
check_database_connection() {
    local db_name=$1
    print_info "Checking connection to database: $db_name"
    
    if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$db_name" -c "SELECT 1;" > /dev/null 2>&1; then
        print_success "Connected to database: $db_name"
        return 0
    else
        print_error "Failed to connect to database: $db_name"
        return 1
    fi
}

# Function to create migration tracking table
create_migrations_table() {
    local db_name=$1
    print_info "Creating migrations tracking table in $db_name"
    
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$db_name" <<EOF
CREATE TABLE IF NOT EXISTS $MIGRATIONS_TABLE (
    id SERIAL PRIMARY KEY,
    migration_file VARCHAR(255) UNIQUE NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checksum VARCHAR(64)
);
EOF
}

# Function to check if migration has been applied
is_migration_applied() {
    local db_name=$1
    local migration_file=$2
    
    local count
    count=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$db_name" -t -c \
        "SELECT COUNT(*) FROM $MIGRATIONS_TABLE WHERE migration_file = '$migration_file';")
    
    if [ "$count" -gt 0 ]; then
        return 0
    else
        return 1
    fi
}

# Function to calculate file checksum
calculate_checksum() {
    local file=$1
    shasum -a 256 "$file" | awk '{print $1}'
}

# Function to record migration
record_migration() {
    local db_name=$1
    local migration_file=$2
    local checksum=$3
    
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$db_name" <<EOF
INSERT INTO $MIGRATIONS_TABLE (migration_file, checksum)
VALUES ('$migration_file', '$checksum')
ON CONFLICT (migration_file) DO NOTHING;
EOF
}

# Function to apply migration
apply_migration() {
    local db_name=$1
    local migration_file=$2
    local sql_file=$3
    
    print_info "Applying migration: $migration_file to $db_name"
    
    # Check if already applied
    if is_migration_applied "$db_name" "$migration_file"; then
        print_warning "Migration $migration_file already applied to $db_name, skipping"
        return 0
    fi
    
    # Calculate checksum
    local checksum
    checksum=$(calculate_checksum "$sql_file")
    
    # Apply migration
    if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$db_name" -f "$sql_file"; then
        record_migration "$db_name" "$migration_file" "$checksum"
        print_success "Migration $migration_file applied successfully to $db_name"
        return 0
    else
        print_error "Failed to apply migration $migration_file to $db_name"
        return 1
    fi
}

# Function to migrate specific database
migrate_database() {
    local db_name=$1
    local migration_file=$2
    
    print_info "Starting migration for database: $db_name"
    
    # Check connection
    if ! check_database_connection "$db_name"; then
        print_error "Cannot proceed with migration for $db_name"
        return 1
    fi
    
    # Create migrations table
    create_migrations_table "$db_name"
    
    # Apply migration
    local sql_file="$SCRIPT_DIR/$migration_file"
    if [ -f "$sql_file" ]; then
        apply_migration "$db_name" "$migration_file" "$sql_file"
    else
        print_error "Migration file not found: $sql_file"
        return 1
    fi
}

# Function to show migration status
show_status() {
    local db_name=$1
    
    print_info "Migration status for $db_name:"
    
    if ! check_database_connection "$db_name"; then
        return 1
    fi
    
    create_migrations_table "$db_name"
    
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$db_name" <<EOF
SELECT 
    migration_file,
    applied_at,
    checksum
FROM $MIGRATIONS_TABLE
ORDER BY applied_at DESC;
EOF
}

# Main migration function
run_migrations() {
    print_info "Starting Mobius database migrations"
    print_info "Database host: $DB_HOST:$DB_PORT"
    
    # Define database migrations
    declare -A DATABASE_MIGRATIONS=(
        ["mobius_app"]="001_app_database.sql"
        ["mobius_clients"]="002_clients_database.sql"
        ["mobius_osquery"]="003_osquery_database.sql"
        ["mobius_audit"]="004_audit_database.sql"
    )
    
    # Track success
    local failed_count=0
    local success_count=0
    
    # Apply migrations
    for db_name in "${!DATABASE_MIGRATIONS[@]}"; do
        migration_file="${DATABASE_MIGRATIONS[$db_name]}"
        
        if migrate_database "$db_name" "$migration_file"; then
            ((success_count++))
        else
            ((failed_count++))
        fi
        
        echo ""
    done
    
    # Summary
    print_info "Migration summary:"
    print_success "Successful: $success_count"
    if [ $failed_count -gt 0 ]; then
        print_error "Failed: $failed_count"
        return 1
    fi
    
    print_success "All migrations completed successfully!"
    return 0
}

# Function to show help
show_help() {
    cat <<EOF
Mobius Database Migration Script

Usage: $0 [command] [options]

Commands:
    migrate             Run all pending migrations (default)
    status              Show migration status for all databases
    migrate-db <name>   Migrate specific database
    status-db <name>    Show status for specific database
    help                Show this help message

Environment Variables:
    DB_HOST             Database host (default: localhost)
    DB_PORT             Database port (default: 5432)
    DB_USER             Database user (default: postgres)
    DB_PASSWORD         Database password (default: postgres)

Examples:
    # Run all migrations
    $0 migrate

    # Show status for all databases
    $0 status

    # Migrate specific database
    $0 migrate-db mobius_app

    # Show status for specific database
    $0 status-db mobius_audit

    # Use custom connection
    DB_HOST=postgres.example.com DB_USER=admin $0 migrate
EOF
}

# Parse command
COMMAND="${1:-migrate}"

case "$COMMAND" in
    migrate)
        run_migrations
        ;;
    status)
        for db_name in mobius_app mobius_clients mobius_osquery mobius_audit; do
            show_status "$db_name"
            echo ""
        done
        ;;
    migrate-db)
        if [ -z "$2" ]; then
            print_error "Database name required"
            show_help
            exit 1
        fi
        
        case "$2" in
            mobius_app)
                migrate_database "$2" "001_app_database.sql"
                ;;
            mobius_clients)
                migrate_database "$2" "002_clients_database.sql"
                ;;
            mobius_osquery)
                migrate_database "$2" "003_osquery_database.sql"
                ;;
            mobius_audit)
                migrate_database "$2" "004_audit_database.sql"
                ;;
            *)
                print_error "Unknown database: $2"
                exit 1
                ;;
        esac
        ;;
    status-db)
        if [ -z "$2" ]; then
            print_error "Database name required"
            show_help
            exit 1
        fi
        show_status "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac
