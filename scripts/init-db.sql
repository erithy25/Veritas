-- ═══════════════════════════════════════════════════════════════
-- Veritas B2B - Database Initialization Script
-- Run automatically by PostgreSQL container on first start
-- ═══════════════════════════════════════════════════════════════

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ── Tenant Management ────────────────────────────────────────

CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    api_key_hash    TEXT NOT NULL,
    mtls_cert_fp    TEXT NOT NULL DEFAULT '',
    jurisdiction    TEXT NOT NULL DEFAULT 'GLOBAL',
    status          TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tenant_policies (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id),
    allow_threshold         REAL NOT NULL DEFAULT 0.30,
    flag_threshold          REAL NOT NULL DEFAULT 0.60,
    flag_urgent_threshold   REAL NOT NULL DEFAULT 0.85,
    block_threshold         REAL NOT NULL DEFAULT 0.86,
    enable_l3               BOOLEAN NOT NULL DEFAULT TRUE,
    max_video_duration_sec  INTEGER NOT NULL DEFAULT 600,
    max_resolution          TEXT NOT NULL DEFAULT '4K',
    c2pa_enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    data_residency_region   TEXT NOT NULL DEFAULT 'eu-central-1',
    data_retention_days     INTEGER NOT NULL DEFAULT 90,
    effective_from          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_until         TIMESTAMPTZ,
    created_by              TEXT NOT NULL DEFAULT 'system',
    UNIQUE(tenant_id, effective_from)
);

CREATE TABLE tenant_rate_limits (
    tenant_id                UUID PRIMARY KEY REFERENCES tenants(id),
    requests_per_second      INTEGER NOT NULL DEFAULT 1000,
    requests_per_day         BIGINT NOT NULL DEFAULT 10000000,
    concurrent_l3_analyses   INTEGER NOT NULL DEFAULT 100
);

-- ── Signed Verdicts ──────────────────────────────────────────

CREATE TABLE signed_verdicts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL UNIQUE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    upload_id       TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    risk_score      REAL NOT NULL,
    reason_codes    TEXT[] NOT NULL DEFAULT '{}',
    verdict_hash    BYTEA NOT NULL,
    signature       BYTEA NOT NULL,
    signing_key_id  TEXT NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'Ed25519',
    cert_chain_url  TEXT NOT NULL DEFAULT '',
    signed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT create_hypertable('signed_verdicts', 'signed_at',
    chunk_time_interval => INTERVAL '1 day');

CREATE INDEX idx_signed_verdicts_tenant ON signed_verdicts (tenant_id, signed_at DESC);
CREATE INDEX idx_signed_verdicts_upload ON signed_verdicts (upload_id);
CREATE INDEX idx_signed_verdicts_verdict ON signed_verdicts (verdict, signed_at DESC);

-- ── Signing Keys ─────────────────────────────────────────────

CREATE TABLE signing_keys (
    key_id          TEXT PRIMARY KEY,
    tenant_id       UUID REFERENCES tenants(id),
    public_key      BYTEA NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'Ed25519',
    hsm_key_handle  TEXT NOT NULL DEFAULT 'local-dev',
    status          TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    valid_until     TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 years'
);

-- ── Moderator Actions ────────────────────────────────────────

CREATE TABLE moderator_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL,
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    reviewer_id     TEXT NOT NULL,
    original_verdict TEXT NOT NULL,
    override_verdict TEXT NOT NULL,
    reason          TEXT NOT NULL,
    review_duration_sec INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT create_hypertable('moderator_actions', 'created_at',
    chunk_time_interval => INTERVAL '7 days');

-- ── Model Versions ───────────────────────────────────────────

CREATE TABLE model_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_name      TEXT NOT NULL,
    version         TEXT NOT NULL,
    s3_path         TEXT NOT NULL DEFAULT '',
    accuracy_metrics JSONB NOT NULL DEFAULT '{}',
    training_data_hash TEXT NOT NULL DEFAULT '',
    deployed_at     TIMESTAMPTZ,
    retired_at      TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'STAGING',
    change_description TEXT NOT NULL DEFAULT '',
    UNIQUE(model_name, version)
);

-- ── Compliance Incidents ─────────────────────────────────────

CREATE TABLE compliance_incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     TEXT UNIQUE,
    scan_id         TEXT,
    incident_type   TEXT NOT NULL,
    severity        TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    reason_codes    TEXT NOT NULL DEFAULT '[]',
    regulation      TEXT NOT NULL DEFAULT '',
    article_reference TEXT NOT NULL DEFAULT '',
    affected_tenants UUID[],
    affected_scans  INTEGER DEFAULT 0,
    root_cause      TEXT,
    resolution      TEXT,
    status          TEXT NOT NULL DEFAULT 'pending_review',
    reported_to_dpa BOOLEAN NOT NULL DEFAULT FALSE,
    reported_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

-- ── EU AI Act Compliance ────────────────────────────────────

CREATE TABLE compliance_audit_log (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id                TEXT NOT NULL UNIQUE,
    scan_id                 TEXT NOT NULL,
    tenant_id               TEXT NOT NULL,
    decision                TEXT NOT NULL,
    risk_score              DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    reason_codes            TEXT NOT NULL DEFAULT '[]',
    model_versions          JSONB NOT NULL DEFAULT '{}',
    human_oversight_required BOOLEAN NOT NULL DEFAULT FALSE,
    regulation              TEXT NOT NULL DEFAULT 'EU_AI_ACT',
    article_reference       TEXT NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT create_hypertable('compliance_audit_log', 'created_at',
    chunk_time_interval => INTERVAL '1 day');

CREATE INDEX idx_compliance_audit_scan ON compliance_audit_log (scan_id);
CREATE INDEX idx_compliance_audit_tenant ON compliance_audit_log (tenant_id, created_at DESC);

CREATE TABLE compliance_model_changes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    change_id       TEXT NOT NULL UNIQUE,
    model_name      TEXT NOT NULL,
    old_version     TEXT NOT NULL,
    new_version     TEXT NOT NULL,
    change_reason   TEXT NOT NULL DEFAULT '',
    regulation      TEXT NOT NULL DEFAULT 'EU_AI_ACT',
    article_reference TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE compliance_audit_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id     TEXT NOT NULL UNIQUE,
    data            JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── DSA Compliance ──────────────────────────────────────────

CREATE TABLE dsa_statements_of_reasons (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    statement_id        TEXT NOT NULL UNIQUE,
    scan_id             TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    decision            TEXT NOT NULL,
    legal_basis         TEXT NOT NULL,
    automated_detection BOOLEAN NOT NULL DEFAULT TRUE,
    facts               TEXT NOT NULL DEFAULT '[]',
    tos_provision       TEXT,
    redress_info        JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

SELECT create_hypertable('dsa_statements_of_reasons', 'created_at',
    chunk_time_interval => INTERVAL '7 days');

CREATE INDEX idx_dsa_sor_scan ON dsa_statements_of_reasons (scan_id);
CREATE INDEX idx_dsa_sor_tenant ON dsa_statements_of_reasons (tenant_id, created_at DESC);

CREATE TABLE dsa_transparency_counters (
    period          TIMESTAMPTZ NOT NULL,
    decision_type   TEXT NOT NULL,
    count           BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (period, decision_type)
);

CREATE TABLE dsa_systemic_risk_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id       TEXT NOT NULL UNIQUE,
    alert_type      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    alert_data      JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending_submission',
    submitted_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── GDPR Compliance ─────────────────────────────────────────

CREATE TABLE scan_processing_metadata (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'processing',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE gdpr_ropa_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    log_id              TEXT NOT NULL,
    period              TIMESTAMPTZ NOT NULL UNIQUE,
    processing_purpose  TEXT NOT NULL,
    data_categories     TEXT NOT NULL,
    data_subjects       TEXT NOT NULL,
    recipients          TEXT NOT NULL,
    retention_period    TEXT NOT NULL,
    scans_processed     BIGINT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE gdpr_erasure_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      TEXT NOT NULL UNIQUE,
    scan_id         TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    records_deleted BIGINT NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'completed',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Seed Development Data ────────────────────────────────────

INSERT INTO tenants (id, name, api_key_hash, jurisdiction) VALUES
    ('550e8400-e29b-41d4-a716-446655440000', 'dev-platform', 'sha256:dev_key_hash', 'EU'),
    ('6ba7b810-9dad-11d1-80b4-00c04fd430c8', 'test-platform', 'sha256:test_key_hash', 'GLOBAL');

INSERT INTO tenant_policies (tenant_id, created_by) VALUES
    ('550e8400-e29b-41d4-a716-446655440000', 'system'),
    ('6ba7b810-9dad-11d1-80b4-00c04fd430c8', 'system');

INSERT INTO tenant_rate_limits (tenant_id) VALUES
    ('550e8400-e29b-41d4-a716-446655440000'),
    ('6ba7b810-9dad-11d1-80b4-00c04fd430c8');

INSERT INTO model_versions (model_name, version, status, change_description, deployed_at) VALUES
    ('vit-l16-general', 'v1.0.0', 'PRODUCTION', 'Initial release', NOW()),
    ('efficientnet-b7-gan', 'v1.0.0', 'PRODUCTION', 'Initial release', NOW()),
    ('tcn-temporal', 'v1.0.0', 'PRODUCTION', 'Initial release', NOW()),
    ('diffusion-artifact-detector', 'v1.0.0', 'PRODUCTION', 'Initial release', NOW()),
    ('syncnet-lipsync', 'v1.0.0', 'PRODUCTION', 'Initial release', NOW());
