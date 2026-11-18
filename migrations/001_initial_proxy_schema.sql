-- CentralWatch Database Migrations
-- 001_initial_proxy_schema.sql
-- Production schema for multi-worker API proxy, audit logs, and usage telemetry.

CREATE TABLE IF NOT EXISTS proxy_services (
    service_name VARCHAR(128) PRIMARY KEY,
    base_url VARCHAR(1024) NOT NULL,
    encrypted_api_key TEXT NOT NULL,
    encrypted_api_key_secondary TEXT,
    header_name VARCHAR(128) NOT NULL DEFAULT 'x-api-key',
    query_param VARCHAR(128),
    bearer_auth BOOLEAN NOT NULL DEFAULT FALSE,
    rate_limit_rpm INTEGER NOT NULL DEFAULT 600,
    monthly_budget_usd NUMERIC(10, 2) NOT NULL DEFAULT 100.00,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS proxy_roles (
    role_name VARCHAR(128) PRIMARY KEY,
    service_name VARCHAR(128) NOT NULL REFERENCES proxy_services(service_name) ON DELETE CASCADE,
    allowed_methods VARCHAR(64)[] NOT NULL DEFAULT '{"GET"}',
    path_pattern VARCHAR(512) NOT NULL DEFAULT '^/',
    encrypted_proxy_token TEXT NOT NULL,
    token_expires_at TIMESTAMP WITH TIME ZONE,
    rate_limit_rpm INTEGER NOT NULL DEFAULT 120,
    daily_quota_requests INTEGER NOT NULL DEFAULT 10000,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS proxy_audit_logs (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    actor_id VARCHAR(128) NOT NULL,
    client_ip VARCHAR(64) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    hmac_signature VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS proxy_usage_history (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(128) NOT NULL,
    role_name VARCHAR(128) NOT NULL,
    method VARCHAR(16) NOT NULL,
    path VARCHAR(512) NOT NULL,
    status_code INTEGER NOT NULL,
    latency_ms NUMERIC(10, 2) NOT NULL,
    client_ip VARCHAR(64) NOT NULL,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    estimated_cost_usd NUMERIC(10, 4) NOT NULL DEFAULT 0.0000,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for fast audit and metrics queries
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON proxy_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_service_created ON proxy_usage_history(service_name, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_role_created ON proxy_usage_history(role_name, created_at DESC);

