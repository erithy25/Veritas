-- ═══════════════════════════════════════════════════════════════
-- Veritas B2B - ClickHouse Schema Initialization
-- High-volume analytics and detection event logging
-- ═══════════════════════════════════════════════════════════════

CREATE DATABASE IF NOT EXISTS veritas;

-- ── Detection Event Logs ────────────────────────────────────

CREATE TABLE IF NOT EXISTS veritas.detection_logs
(
    scan_id         String,
    tenant_id       String,
    upload_id       String,
    tier            Enum8('L1' = 1, 'L2' = 2, 'L3' = 3),
    model_name      String,
    score           Float64,
    duration_ms     UInt32,
    result          String,
    metadata        String,
    timestamp       DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, scan_id)
TTL timestamp + INTERVAL 365 DAY;

-- ── Verdict Analytics ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS veritas.verdict_analytics
(
    scan_id         String,
    tenant_id       String,
    verdict         Enum8('ALLOW' = 1, 'FLAG' = 2, 'FLAG_URGENT' = 3, 'BLOCK' = 4),
    risk_score      Float64,
    l1_score        Float64,
    l2_score        Float64,
    l3_score        Float64,
    context_multiplier Float64,
    tiers_executed  UInt8,
    total_duration_ms UInt32,
    reason_codes    Array(String),
    public_figure   UInt8,
    political_context UInt8,
    timestamp       DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp)
TTL timestamp + INTERVAL 365 DAY;

-- ── EU AI Act Decision Audit Log (High Volume) ─────────────

CREATE TABLE IF NOT EXISTS veritas.ai_act_decisions
(
    audit_id                String,
    scan_id                 String,
    tenant_id               String,
    decision                String,
    risk_score              Float64,
    reason_codes            Array(String),
    human_oversight_required UInt8,
    timestamp               DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp)
TTL timestamp + INTERVAL 2190 DAY;  -- 6 years retention for regulatory compliance

-- ── Compliance Event Stream ─────────────────────────────────

CREATE TABLE IF NOT EXISTS veritas.compliance_events
(
    event_id        String,
    event_type      String,
    scan_id         String,
    tenant_id       String,
    regulation      String,
    details         String,
    timestamp       DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (regulation, timestamp)
TTL timestamp + INTERVAL 2190 DAY;

-- ── Request / API Metrics ───────────────────────────────────

CREATE TABLE IF NOT EXISTS veritas.api_request_logs
(
    request_id      String,
    tenant_id       String,
    method          String,
    path            String,
    status_code     UInt16,
    latency_ms      UInt32,
    request_size    UInt64,
    response_size   UInt64,
    user_agent      String,
    source_ip       String,
    timestamp       DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp)
TTL timestamp + INTERVAL 90 DAY;

-- ── Materialized Views for Dashboards ───────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS veritas.hourly_verdict_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, verdict)
AS
SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    verdict,
    count() AS total,
    avg(risk_score) AS avg_risk_score,
    avg(total_duration_ms) AS avg_duration_ms
FROM veritas.verdict_analytics
GROUP BY tenant_id, hour, verdict;

CREATE MATERIALIZED VIEW IF NOT EXISTS veritas.daily_detection_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, tier, model_name)
AS
SELECT
    tenant_id,
    toStartOfDay(timestamp) AS day,
    tier,
    model_name,
    count() AS total,
    avg(score) AS avg_score,
    avg(duration_ms) AS avg_duration_ms
FROM veritas.detection_logs
GROUP BY tenant_id, day, tier, model_name;
