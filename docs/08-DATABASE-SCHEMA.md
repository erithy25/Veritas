# Veritas B2B - Database Schema Design

**Version**: 1.0.0
**Last Updated**: 2026-03-08

---

## Table of Contents

1. [Database Architecture Overview](#1-database-architecture-overview)
2. [PostgreSQL Schema (Signatures & Config)](#2-postgresql-schema)
3. [ClickHouse Schema (Analytics & Logs)](#3-clickhouse-schema)
4. [Redis Data Structures](#4-redis-data-structures)
5. [Data Lifecycle Management](#5-data-lifecycle-management)

---

## 1. Database Architecture Overview

### 1.1 Database Selection Rationale

| Database | Use Case | Rationale |
|----------|----------|-----------|
| **PostgreSQL + TimescaleDB** | Signatures, tenant config, moderator actions, compliance records | ACID transactions for legal evidence. Relational integrity. TimescaleDB for time-series queries on scan history. |
| **ClickHouse** | Detection logs, analytics, dashboards, reporting | Column-oriented design provides 100x compression. Sub-second OLAP queries over billions of rows. Optimal for high-volume append-only workloads. |
| **Redis Cluster** | Hash cache, auth token cache, rate limiting, real-time metrics | Sub-millisecond reads. Pub/Sub for dashboard updates. Atomic operations for rate limiting. |

### 1.2 No Biometric Data in Any Database

All databases store **only** non-biometric data:
- Detection scores (numbers)
- Metadata (strings, timestamps)
- Cryptographic signatures (bytes)
- Configuration (JSON/relational)

Biometric data (face crops, feature vectors, rPPG signals) exists **only in RAM** and is never written to any persistent store.

---

## 2. PostgreSQL Schema

### 2.1 Tenant Management

```sql
-- Tenant registry
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    api_key_hash    TEXT NOT NULL,
    mtls_cert_fp    TEXT NOT NULL,
    jurisdiction    TEXT NOT NULL DEFAULT 'GLOBAL',
    status          TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tenant-specific policy configuration
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
    report_frequency        TEXT NOT NULL DEFAULT 'MONTHLY',
    data_residency_region   TEXT NOT NULL DEFAULT 'eu-central-1',
    effective_from          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_until         TIMESTAMPTZ,
    created_by              TEXT NOT NULL,
    UNIQUE(tenant_id, effective_from)
);

CREATE INDEX idx_tenant_policies_active ON tenant_policies (tenant_id, effective_from)
    WHERE effective_until IS NULL;

-- Tenant rate limits
CREATE TABLE tenant_rate_limits (
    tenant_id                UUID PRIMARY KEY REFERENCES tenants(id),
    requests_per_second      INTEGER NOT NULL DEFAULT 1000,
    requests_per_day         BIGINT NOT NULL DEFAULT 10000000,
    concurrent_l3_analyses   INTEGER NOT NULL DEFAULT 100
);

-- Custom policy rules per tenant
CREATE TABLE tenant_custom_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    rule_name   TEXT NOT NULL,
    rule_type   TEXT NOT NULL, -- 'ALLOWLIST', 'BLOCKLIST', 'THRESHOLD_OVERRIDE', 'GEOGRAPHIC'
    conditions  JSONB NOT NULL,
    action      TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 0,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 2.2 Cryptographic Signatures

```sql
-- Signed verdicts (legal evidence chain)
CREATE TABLE signed_verdicts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL UNIQUE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    upload_id       TEXT NOT NULL,
    verdict         TEXT NOT NULL, -- 'ALLOW', 'FLAG', 'FLAG_URGENT', 'BLOCK'
    risk_score      REAL NOT NULL,
    reason_codes    TEXT[] NOT NULL,
    verdict_hash    BYTEA NOT NULL, -- SHA-512 of canonical verdict
    signature       BYTEA NOT NULL, -- Ed25519 signature
    signing_key_id  TEXT NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'Ed25519',
    cert_chain_url  TEXT NOT NULL,
    signed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- TimescaleDB hypertable for time-based queries
SELECT create_hypertable('signed_verdicts', 'signed_at',
    chunk_time_interval => INTERVAL '1 day');

CREATE INDEX idx_signed_verdicts_tenant ON signed_verdicts (tenant_id, signed_at DESC);
CREATE INDEX idx_signed_verdicts_upload ON signed_verdicts (upload_id);
CREATE INDEX idx_signed_verdicts_verdict ON signed_verdicts (verdict, signed_at DESC);

-- Signing key registry
CREATE TABLE signing_keys (
    key_id          TEXT PRIMARY KEY,
    tenant_id       UUID REFERENCES tenants(id), -- NULL for system-wide keys
    public_key      BYTEA NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'Ed25519',
    hsm_key_handle  TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'ROTATED', 'REVOKED'
    created_at      TIMESTAMPTZ NOT NULL,
    rotated_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    valid_until     TIMESTAMPTZ NOT NULL
);
```

### 2.3 Moderator Actions

```sql
-- Human override decisions
CREATE TABLE moderator_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES signed_verdicts(scan_id),
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

CREATE INDEX idx_moderator_actions_reviewer ON moderator_actions (reviewer_id, created_at DESC);

-- Reviewer registry
CREATE TABLE reviewers (
    id                  TEXT PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(id),
    name                TEXT NOT NULL,
    role                TEXT NOT NULL DEFAULT 'MODERATOR', -- 'MODERATOR', 'SENIOR_MODERATOR', 'ADMIN'
    training_completed  BOOLEAN NOT NULL DEFAULT FALSE,
    training_date       DATE,
    certification_valid_until DATE,
    active              BOOLEAN NOT NULL DEFAULT TRUE
);
```

### 2.4 Compliance Records

```sql
-- EU AI Act incident records
CREATE TABLE compliance_incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_type   TEXT NOT NULL, -- 'DATA_BREACH', 'RESIDENCY_VIOLATION', 'ACCURACY_DEGRADATION', etc.
    severity        TEXT NOT NULL, -- 'P1', 'P2', 'P3', 'P4'
    description     TEXT NOT NULL,
    affected_tenants UUID[],
    affected_scans  INTEGER,
    root_cause      TEXT,
    resolution      TEXT,
    reported_to_dpa BOOLEAN NOT NULL DEFAULT FALSE,
    reported_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ
);

-- Model version registry (for reproducibility)
CREATE TABLE model_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_name      TEXT NOT NULL, -- 'vit', 'efficientnet', 'tcn', 'diffusion_detector', 'lip_sync'
    version         TEXT NOT NULL,
    s3_path         TEXT NOT NULL,
    accuracy_metrics JSONB NOT NULL, -- {f1, precision, recall, fpr, fnr}
    training_data_hash TEXT NOT NULL,
    deployed_at     TIMESTAMPTZ,
    retired_at      TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'STAGING', -- 'STAGING', 'CANARY', 'PRODUCTION', 'RETIRED'
    change_description TEXT NOT NULL,
    UNIQUE(model_name, version)
);

-- Data Processing Agreements
CREATE TABLE data_processing_agreements (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    dpa_version     TEXT NOT NULL,
    signed_at       DATE NOT NULL,
    valid_until     DATE,
    document_hash   TEXT NOT NULL, -- SHA-256 of signed DPA document
    sub_processors  TEXT[] NOT NULL, -- List of sub-processors
    data_residency  TEXT NOT NULL
);
```

---

## 3. ClickHouse Schema

### 3.1 Detection Logs

```sql
-- Primary detection log (billions of rows)
CREATE TABLE detection_logs (
    scan_id         UUID,
    tenant_id       UUID,
    upload_id       String,
    scanned_at      DateTime64(3, 'UTC'),

    -- Video metadata
    video_format    LowCardinality(String),
    video_duration_sec Float32,
    video_resolution   LowCardinality(String),
    faces_detected  UInt8,

    -- L1 results
    l1_completed    Bool,
    l1_duration_ms  UInt16,
    l1_hash_match   Bool,
    l1_hash_match_id String DEFAULT '',
    l1_metadata_score Float32,
    l1_compression_score Float32,
    l1_c2pa_valid   Nullable(Bool),

    -- L2 results
    l2_completed    Bool DEFAULT false,
    l2_duration_ms  UInt16 DEFAULT 0,
    l2_flicker_score Float32 DEFAULT 0,
    l2_rppg_score   Float32 DEFAULT 0,
    l2_rppg_quality Float32 DEFAULT 0,
    l2_eye_score    Float32 DEFAULT 0,
    l2_skin_score   Float32 DEFAULT 0,

    -- L3 results
    l3_completed    Bool DEFAULT false,
    l3_duration_ms  UInt16 DEFAULT 0,
    l3_vit_score    Float32 DEFAULT 0,
    l3_efficientnet_score Float32 DEFAULT 0,
    l3_tcn_score    Float32 DEFAULT 0,
    l3_diffusion_score Float32 DEFAULT 0,
    l3_lipsync_score Float32 DEFAULT 0,
    l3_ensemble_score Float32 DEFAULT 0,
    l3_model_agreement Float32 DEFAULT 0,

    -- Scoring
    risk_score      Float32,
    context_multiplier Float32 DEFAULT 1.0,
    public_figure_detected Bool DEFAULT false,
    political_context_score Float32 DEFAULT 0,

    -- Verdict
    verdict         LowCardinality(String), -- ALLOW, FLAG, FLAG_URGENT, BLOCK
    reason_codes    Array(String),
    tiers_used      Array(UInt8),

    -- Processing metadata
    processing_region LowCardinality(String),
    edge_node       LowCardinality(String) DEFAULT '',
    total_duration_ms UInt32,
    model_versions  Map(String, String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(scanned_at)
ORDER BY (tenant_id, scanned_at, scan_id)
TTL scanned_at + INTERVAL 2 YEAR
SETTINGS index_granularity = 8192;

-- Materialized view for per-tenant hourly aggregates
CREATE MATERIALIZED VIEW detection_hourly_agg
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, verdict)
AS SELECT
    tenant_id,
    toStartOfHour(scanned_at) AS hour,
    verdict,
    count() AS scan_count,
    avg(risk_score) AS avg_risk_score,
    avg(total_duration_ms) AS avg_duration_ms,
    countIf(l3_completed) AS l3_count,
    countIf(public_figure_detected) AS public_figure_count
FROM detection_logs
GROUP BY tenant_id, hour, verdict;

-- Materialized view for model accuracy tracking
CREATE MATERIALIZED VIEW model_accuracy_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (model_name, day)
AS SELECT
    toDate(scanned_at) AS day,
    'vit' AS model_name,
    countIf(l3_vit_score > 0.5 AND verdict = 'BLOCK') AS true_positives,
    countIf(l3_vit_score > 0.5 AND verdict = 'ALLOW') AS false_positives,
    countIf(l3_vit_score <= 0.5 AND verdict = 'BLOCK') AS false_negatives,
    countIf(l3_vit_score <= 0.5 AND verdict = 'ALLOW') AS true_negatives
FROM detection_logs
WHERE l3_completed = true
GROUP BY day;
```

### 3.2 Compliance Event Log

```sql
CREATE TABLE compliance_events (
    event_id        UUID,
    event_type      LowCardinality(String),
    timestamp       DateTime64(3, 'UTC'),
    tenant_id       UUID,
    jurisdiction    LowCardinality(String),
    scan_id         Nullable(UUID),

    -- AI Act fields
    risk_classification LowCardinality(String) DEFAULT 'HIGH',
    human_oversight_applied Bool DEFAULT false,

    -- GDPR fields
    biometric_processed Bool DEFAULT false,
    data_residency_compliant Bool DEFAULT true,
    retention_policy LowCardinality(String) DEFAULT 'ZERO_RETENTION',

    -- DSA fields
    content_moderation_decision Bool DEFAULT false,
    appeal_eligible Bool DEFAULT false,

    -- Event details
    details         String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, event_type, timestamp)
TTL timestamp + INTERVAL 10 YEAR;
```

### 3.3 System Metrics Log

```sql
-- High-frequency system metrics (for analytics beyond Prometheus retention)
CREATE TABLE system_metrics (
    timestamp       DateTime64(3, 'UTC'),
    region          LowCardinality(String),
    service         LowCardinality(String),
    metric_name     LowCardinality(String),
    metric_value    Float64,
    labels          Map(String, String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (service, metric_name, timestamp)
TTL timestamp + INTERVAL 90 DAY;
```

### 3.4 Useful ClickHouse Queries

```sql
-- Detection volume per tenant (last 24 hours)
SELECT
    t.name AS tenant_name,
    verdict,
    count() AS scan_count,
    avg(risk_score) AS avg_score,
    avg(total_duration_ms) AS avg_latency
FROM detection_logs d
JOIN tenants t ON d.tenant_id = t.id
WHERE scanned_at > now() - INTERVAL 24 HOUR
GROUP BY t.name, verdict
ORDER BY scan_count DESC;

-- Top reason codes (last 7 days)
SELECT
    reason_code,
    count() AS occurrence_count,
    avg(risk_score) AS avg_score
FROM detection_logs
ARRAY JOIN reason_codes AS reason_code
WHERE scanned_at > now() - INTERVAL 7 DAY
  AND verdict IN ('FLAG', 'BLOCK')
GROUP BY reason_code
ORDER BY occurrence_count DESC
LIMIT 20;

-- Hourly detection trend (for deepfake wave detection)
SELECT
    toStartOfHour(scanned_at) AS hour,
    countIf(verdict = 'BLOCK') AS blocks,
    countIf(verdict = 'FLAG') AS flags,
    countIf(verdict = 'ALLOW') AS allows,
    countIf(verdict = 'BLOCK') / count() AS block_rate
FROM detection_logs
WHERE scanned_at > now() - INTERVAL 48 HOUR
GROUP BY hour
ORDER BY hour;

-- Model accuracy comparison
SELECT
    day,
    model_name,
    true_positives / (true_positives + false_negatives) AS recall,
    true_positives / (true_positives + false_positives) AS precision,
    2 * true_positives / (2 * true_positives + false_positives + false_negatives) AS f1
FROM model_accuracy_daily
WHERE day > today() - 30
ORDER BY day, model_name;
```

---

## 4. Redis Data Structures

### 4.1 Hash Database (Deepfake Detection)

```
Key Pattern: hash:p:{perceptual_hash_hex}
Value: JSON { "id": "DF-2026-44821", "source": "partner_feed", "added": "2026-03-01", "type": "face_swap" }
TTL: None (permanent until explicitly removed)
Estimated Size: 100M keys × ~200 bytes = ~20 GB

Key Pattern: hash:d:{dhash_hex}
Value: JSON (same structure)

Key Pattern: hash:a:{ahash_hex}
Value: JSON (same structure)
```

### 4.2 Auth Token Cache

```
Key Pattern: auth:jwt:{token_hash}
Value: JSON { "tenant_id": "uuid", "permissions": [...], "validated_at": "ISO8601" }
TTL: 300 seconds (5 minutes)
Estimated Size: ~100K concurrent keys × ~500 bytes = ~50 MB
```

### 4.3 Rate Limiting

```
Key Pattern: rl:sec:{tenant_id}:{epoch_second}
Value: Counter (INCR)
TTL: 2 seconds
Operation: INCR + compare against tenant limit

Key Pattern: rl:day:{tenant_id}:{date}
Value: Counter (INCR)
TTL: 86400 seconds (1 day)
```

### 4.4 Real-Time Dashboard Metrics

```
Key Pattern: rt:detections:{tenant_id}
Type: Sorted Set (score = timestamp, member = scan_id)
TTL: 3600 seconds (1 hour window)
Purpose: Recent detections for real-time feed

Key Pattern: rt:stats:{tenant_id}:{metric}
Type: String (counter)
TTL: 86400 seconds
Purpose: Rolling counters for dashboard widgets

Pub/Sub Channel: veritas:verdicts:{tenant_id}
Purpose: Real-time verdict push to WebSocket gateway
```

### 4.5 Edge Node Hash Subset

```
-- On edge Redis replicas:
Key Pattern: Same as main hash database
Subset: Top 10M most relevant hashes (synced via Redis replication)
TTL: None
Sync: Redis replication stream from regional master
```

---

## 5. Data Lifecycle Management

### 5.1 Retention Summary

| Data | Storage | Retention | Deletion Method |
|------|---------|-----------|----------------|
| Biometric vectors | RAM only | 0 (immediate) | secure_memzero() |
| Video frames | RAM only | 0 (immediate) | secure_memzero() |
| Detection logs | ClickHouse | 2 years | TTL auto-drop partitions |
| Signed verdicts | PostgreSQL | 10 years | Manual archival to S3 Glacier |
| Compliance events | ClickHouse | 10 years | TTL (extended retention) |
| Moderator actions | PostgreSQL | 10 years | Manual archival |
| Auth token cache | Redis | 5 minutes | TTL auto-expire |
| Rate limit counters | Redis | 1 day | TTL auto-expire |
| Hash database | Redis | Indefinite | Manual curation |
| Model artifacts | S3 | Indefinite | Manual curation |
| System metrics | ClickHouse | 90 days | TTL auto-drop |

### 5.2 Archival Process

For data exceeding active retention but requiring long-term storage:

1. **ClickHouse → S3**: Monthly partitions older than 2 years exported to Parquet on S3
2. **PostgreSQL → S3**: Annual archives of signed verdicts older than 2 years to S3
3. **S3 → Glacier**: Data older than 3 years moved to Glacier Deep Archive
4. **Glacier retention**: 10 years from creation, then permanent deletion

### 5.3 Partition Management (ClickHouse)

```sql
-- Automatic partition management
-- Partitions older than 2 years are dropped automatically by TTL
-- Before dropping, export to S3:

-- Export old partitions (run monthly via cron job)
ALTER TABLE detection_logs
    FREEZE PARTITION toYYYYMM(now() - INTERVAL 25 MONTH);
-- Then upload frozen partition to S3 and drop

-- Verify partition sizes
SELECT
    partition,
    name,
    rows,
    formatReadableSize(bytes_on_disk) AS size
FROM system.parts
WHERE table = 'detection_logs'
ORDER BY partition;
```
