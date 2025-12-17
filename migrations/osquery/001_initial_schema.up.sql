-- Migration: Initial schema for mobius-osquery database
-- Description: OSQuery results, queries, and packs

-- OSQuery results
CREATE TABLE IF NOT EXISTS osquery_results (
    id UUID DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL,
    query_name VARCHAR(255) NOT NULL,
    calendar_time TIMESTAMP NOT NULL,
    unix_time BIGINT NOT NULL,
    epoch BIGINT,
    counter BIGINT,
    columns JSONB NOT NULL,
    action VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

-- OSQuery scheduled queries
CREATE TABLE IF NOT EXISTS osquery_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    query TEXT NOT NULL,
    interval INTEGER NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- OSQuery packs
CREATE TABLE IF NOT EXISTS osquery_packs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    platform VARCHAR(50),
    version VARCHAR(50),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Pack queries relationship
CREATE TABLE IF NOT EXISTS osquery_pack_queries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pack_id UUID REFERENCES osquery_packs(id) ON DELETE CASCADE,
    query_id UUID REFERENCES osquery_queries(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(pack_id, query_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_osquery_results_client_id ON osquery_results(client_id);
CREATE INDEX IF NOT EXISTS idx_osquery_results_query_name ON osquery_results(query_name);
CREATE INDEX IF NOT EXISTS idx_osquery_results_calendar_time ON osquery_results(calendar_time DESC);
CREATE INDEX IF NOT EXISTS idx_osquery_results_columns ON osquery_results USING gin(columns);
CREATE INDEX IF NOT EXISTS idx_osquery_queries_name ON osquery_queries(name);
CREATE INDEX IF NOT EXISTS idx_osquery_queries_enabled ON osquery_queries(enabled);
CREATE INDEX IF NOT EXISTS idx_osquery_packs_name ON osquery_packs(name);
CREATE INDEX IF NOT EXISTS idx_osquery_pack_queries_pack_id ON osquery_pack_queries(pack_id);
CREATE INDEX IF NOT EXISTS idx_osquery_pack_queries_query_id ON osquery_pack_queries(query_id);

-- Trigger to update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_osquery_queries_updated_at BEFORE UPDATE ON osquery_queries
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_osquery_packs_updated_at BEFORE UPDATE ON osquery_packs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Partition osquery_results by month for better performance
CREATE TABLE IF NOT EXISTS osquery_results_partitioned (
    id UUID DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL,
    query_name VARCHAR(255) NOT NULL,
    calendar_time TIMESTAMP NOT NULL,
    unix_time BIGINT NOT NULL,
    epoch BIGINT,
    counter BIGINT,
    columns JSONB NOT NULL,
    action VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (id, calendar_time)
) PARTITION BY RANGE (calendar_time);
