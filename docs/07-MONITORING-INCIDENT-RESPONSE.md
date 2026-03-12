# Veritas B2B - Monitoring & Incident Response

**Version**: 1.0.0
**Last Updated**: 2026-03-08

---

## Table of Contents

1. [Observability Stack](#1-observability-stack)
2. [Metrics Architecture](#2-metrics-architecture)
3. [Alerting Strategy](#3-alerting-strategy)
4. [SLO/SLI Definitions](#4-slosli-definitions)
5. [Dashboards](#5-dashboards)
6. [Deepfake Wave Detection](#6-deepfake-wave-detection)
7. [Incident Management](#7-incident-management)
8. [Runbooks](#8-runbooks)
9. [Post-Incident Process](#9-post-incident-process)

---

## 1. Observability Stack

### 1.1 Technology Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Metrics Collection | Prometheus (HA pair per region) | Time-series metrics from all services |
| Metrics Storage | Thanos or Cortex | Long-term metric storage, cross-region queries |
| Dashboards | Grafana (HA) | Visualization, exploration, alerting |
| Distributed Tracing | OpenTelemetry + Jaeger/Tempo | Request tracing across services |
| Log Aggregation | OpenSearch (formerly Elasticsearch) | Structured log storage and search |
| Log Shipping | Fluent Bit (DaemonSet) | Log collection from containers |
| Alerting | Grafana Alerting + PagerDuty | Multi-channel alert routing |
| Synthetic Monitoring | Grafana Synthetic Monitoring | Proactive API health checks |
| Status Page | Atlassian Statuspage or Instatus | Public status communication |

### 1.2 Data Flow

```
Services (metrics) → Prometheus → Thanos Sidecar → Thanos Store → Grafana
Services (traces)  → OTel Collector → Tempo/Jaeger → Grafana
Services (logs)    → Fluent Bit → OpenSearch → Grafana/Kibana
Alerts             → Grafana Alerting → PagerDuty → On-call engineer
```

### 1.3 Retention Policies

| Data Type | Hot Storage | Warm Storage | Cold Storage |
|-----------|------------|-------------|-------------|
| Metrics | 15 days (Prometheus) | 90 days (Thanos) | 1 year (S3/GCS) |
| Traces | 7 days (Tempo) | 30 days (S3) | - |
| Logs | 30 days (OpenSearch) | 90 days (S3) | 1 year (Glacier) |
| Alerts | Indefinite (PagerDuty) | - | - |

---

## 2. Metrics Architecture

### 2.1 Service-Level Metrics

Every service exposes the following standard metrics at `/metrics`:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `veritas_request_duration_seconds` | Histogram | service, method, status | Request latency distribution |
| `veritas_request_total` | Counter | service, method, status | Total request count |
| `veritas_active_requests` | Gauge | service | Currently processing requests |
| `veritas_errors_total` | Counter | service, error_type | Error count by type |

### 2.2 Detection-Specific Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `veritas_l1_scan_duration_ms` | Histogram | result | L1 scan latency |
| `veritas_l1_hash_hits_total` | Counter | match_type | Hash database hits |
| `veritas_l2_scan_duration_ms` | Histogram | result, technique | L2 scan latency per technique |
| `veritas_l2_rppg_signal_quality` | Histogram | - | rPPG signal quality distribution |
| `veritas_l3_inference_duration_ms` | Histogram | model | Per-model inference latency |
| `veritas_l3_ensemble_confidence` | Histogram | - | Ensemble confidence distribution |
| `veritas_detection_result_total` | Counter | tier, action, tenant | Detection outcomes |
| `veritas_false_positive_rate` | Gauge | model, period | Tracked FP rate |
| `veritas_false_negative_rate` | Gauge | model, period | Tracked FN rate |
| `veritas_scoring_duration_ms` | Histogram | - | Risk scoring latency |
| `veritas_signing_duration_ms` | Histogram | - | Cryptographic signing latency |

### 2.3 Infrastructure Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `veritas_kafka_consumer_lag` | Gauge | topic, consumer_group | Kafka consumer lag (messages) |
| `veritas_kafka_produce_duration_ms` | Histogram | topic | Kafka produce latency |
| `veritas_redis_operation_duration_ms` | Histogram | operation | Redis operation latency |
| `veritas_redis_memory_usage_bytes` | Gauge | node | Redis memory consumption |
| `veritas_clickhouse_query_duration_ms` | Histogram | query_type | ClickHouse query latency |
| `veritas_gpu_utilization_percent` | Gauge | node, gpu_id | GPU utilization |
| `veritas_gpu_memory_usage_bytes` | Gauge | node, gpu_id | GPU memory usage |
| `veritas_triton_queue_depth` | Gauge | model | Triton inference queue depth |
| `veritas_triton_inference_count` | Counter | model, status | Triton inference count |
| `veritas_hsm_operation_duration_ms` | Histogram | operation | HSM operation latency |
| `veritas_edge_request_latency_ms` | Histogram | edge_location | Edge node request latency |
| `veritas_edge_l1_hit_rate` | Gauge | edge_location | Edge L1 pre-screening hit rate |

### 2.4 Compliance Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `veritas_zero_retention_verified` | Gauge | node | Zero-retention compliance (1=OK, 0=FAIL) |
| `veritas_data_residency_violations_total` | Counter | tenant, region | Cross-boundary data violations |
| `veritas_human_review_queue_depth` | Gauge | tenant | Pending human reviews |
| `veritas_human_review_duration_seconds` | Histogram | reviewer | Time spent on human review |
| `veritas_compliance_report_status` | Gauge | report_type | Report generation status |
| `veritas_audit_log_integrity` | Gauge | - | Audit log chain integrity |

---

## 3. Alerting Strategy

### 3.1 Alert Severity Levels

| Level | Severity | Response Time | Notification Channel | Example |
|-------|----------|--------------|---------------------|---------|
| P1 | Critical | 5 minutes | PagerDuty (phone call) | System down, data breach, zero-retention failure |
| P2 | High | 15 minutes | PagerDuty (push + SMS) | Detection accuracy degradation, HSM unreachable |
| P3 | Medium | 1 hour | Slack #alerts + email | High Kafka lag, GPU utilization sustained >90% |
| P4 | Low | 4 hours | Slack #monitoring | Elevated error rates, slow queries |
| P5 | Info | Next business day | Slack #monitoring | Capacity planning warnings |

### 3.2 Critical Alerts (P1)

| Alert Name | Condition | Description |
|-----------|-----------|-------------|
| `VeritasSystemDown` | All gateway pods unhealthy for > 1 min | Complete system outage |
| `ZeroRetentionViolation` | `veritas_zero_retention_verified == 0` on any node | Biometric data may have persisted |
| `DataResidencyBreach` | `veritas_data_residency_violations_total` increased | Data processed outside allowed region |
| `HSMUnreachable` | HSM health check fails for > 2 min | Cannot sign verdicts |
| `SigningFailureRate` | Signing error rate > 5% for 5 min | Compromised audit trail |
| `KafkaClusterDown` | < 2 Kafka brokers healthy | Message pipeline broken |
| `AuditLogCorruption` | `veritas_audit_log_integrity == 0` | Audit chain broken |

### 3.3 High Priority Alerts (P2)

| Alert Name | Condition | Description |
|-----------|-----------|-------------|
| `DetectionAccuracyDegradation` | FP rate > 0.05% or FN rate > 0.5% for 1 hour | Models may need retraining |
| `L3InferenceFailureRate` | L3 error rate > 2% for 10 min | GPU/model issues |
| `GatewayLatencyHigh` | P99 latency > 500ms for 15 min | Performance degradation |
| `HumanReviewQueueBacklog` | Queue depth > 500 for > 2 hours | Insufficient moderator capacity |
| `DeepfakeWaveDetected` | Detection rate > 3x baseline for 30 min | Potential coordinated deepfake campaign |
| `ModelServingError` | Triton returning errors > 1% | Model serving issues |
| `RedisClusterDegraded` | < 4 Redis nodes healthy | Reduced cache capacity |

### 3.4 Medium Priority Alerts (P3)

| Alert Name | Condition | Description |
|-----------|-----------|-------------|
| `KafkaConsumerLagHigh` | Consumer lag > 50K messages for 15 min | Processing falling behind |
| `GPUUtilizationHigh` | GPU utilization > 90% for 30 min | May need scaling |
| `ClickHouseSlowQueries` | P95 query time > 5s for 30 min | Database performance issue |
| `EdgeNodeUnhealthy` | Edge node health check fails for > 5 min | Regional latency impact |
| `CertificateExpiringSoon` | TLS certificate expires in < 14 days | Certificate renewal needed |
| `ComplianceReportDelayed` | Scheduled report not generated within 24 hours | Reporting SLA at risk |

### 3.5 Alert Routing

```
P1/P2 Alerts → PagerDuty → On-Call Engineer (primary)
                         → On-Call Engineer (secondary, if no ack in 5 min)
                         → Engineering Manager (if no ack in 15 min)

P3 Alerts → Slack #veritas-alerts → On-Call Engineer reviews in 1 hour

P4/P5 Alerts → Slack #veritas-monitoring → Reviewed in daily standup

Compliance Alerts (any severity) → Also routed to:
  → Slack #veritas-compliance
  → Compliance Officer email
  → (P1 only) DPO phone notification
```

---

## 4. SLO/SLI Definitions

### 4.1 Service Level Indicators (SLIs)

| SLI | Definition | Measurement |
|-----|-----------|-------------|
| Availability | % of successful responses (non-5xx) | `sum(rate(veritas_request_total{status!~"5.."})) / sum(rate(veritas_request_total))` |
| Latency (L1+L2) | P99 response time for L1+L2 analysis | `histogram_quantile(0.99, veritas_request_duration_seconds{path="/analyze"})` |
| Latency (L1+L2+L3) | P99 response time for full analysis | Same, filtered for L3-included requests |
| Detection Accuracy | F1 score against labeled test set | Computed from periodic validation runs |
| Signing Success | % of verdicts successfully signed | `sum(rate(veritas_signing_total{status="success"})) / sum(rate(veritas_signing_total))` |
| Zero-Retention | % of time zero-retention is verified | `avg(veritas_zero_retention_verified)` |

### 4.2 Service Level Objectives (SLOs)

| SLO | Target | Error Budget (30 days) |
|-----|--------|----------------------|
| API Availability | 99.99% | 4.32 minutes downtime |
| L1+L2 Latency P99 | < 200ms | N/A (latency target) |
| L1+L2+L3 Latency P99 | < 2s | N/A (latency target) |
| Detection Accuracy (F1) | > 0.98 | N/A (accuracy target) |
| False Positive Rate | < 0.01% | N/A (accuracy target) |
| Signing Success | 99.999% | 26 seconds failure/month |
| Zero-Retention Compliance | 100% | 0 seconds non-compliance |
| Data Residency Compliance | 100% | 0 violations |

### 4.3 Error Budget Policy

| Error Budget Remaining | Action |
|----------------------|--------|
| > 50% | Normal operations, feature development continues |
| 25-50% | Increase monitoring, no risky deployments |
| 10-25% | Feature freeze, focus on reliability improvements |
| < 10% | Incident-level response, all hands on reliability |
| 0% (exhausted) | Post-mortem required, remediation plan before next deployment |

---

## 5. Dashboards

### 5.1 Dashboard Hierarchy

| Dashboard | Audience | Refresh Rate |
|-----------|---------|-------------|
| Executive Overview | C-level, board | 5 minutes |
| Operations Overview | SRE, on-call | 10 seconds |
| Detection Pipeline | ML team, detection engineers | 30 seconds |
| Per-Tenant View | Customer success, tenant operations | 1 minute |
| Compliance Status | Compliance team, auditors | 1 minute |
| Edge Network | Network team | 30 seconds |
| GPU Cluster | ML infrastructure team | 10 seconds |
| Kafka & Data | Data platform team | 30 seconds |
| Cost Dashboard | Finance, engineering leadership | 1 hour |

### 5.2 Operations Overview Dashboard Panels

```
┌──────────────────────────────────────────────────────┐
│ VERITAS OPERATIONS OVERVIEW                    🟢 OK │
├──────────────┬──────────────┬──────────────┬─────────┤
│ RPS: 12,431  │ P50: 42ms    │ P99: 187ms   │ Err: 0% │
├──────────────┴──────────────┴──────────────┴─────────┤
│ Request Rate (24h)                                    │
│ ████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░ │
├───────────────────────┬──────────────────────────────┤
│ Detection Outcomes    │ Kafka Consumer Lag            │
│ ■ ALLOW: 94.2%       │ L1: 234 msgs (OK)            │
│ ■ FLAG:   4.8%       │ L2: 1,203 msgs (OK)          │
│ ■ BLOCK:  1.0%       │ L3: 89 msgs (OK)             │
├───────────────────────┼──────────────────────────────┤
│ GPU Utilization       │ Active Alerts                 │
│ ██████████░ 68%      │ P1: 0  P2: 0  P3: 1  P4: 2  │
│ A100 Cluster          │ ⚠ ClickHouse slow queries    │
├───────────────────────┼──────────────────────────────┤
│ Error Budget (30d)    │ Human Review Queue            │
│ Avail: 98% remaining │ Depth: 23  Avg: 2.3min       │
│ ████████████████████░ │ Reviewers online: 4          │
└───────────────────────┴──────────────────────────────┘
```

### 5.3 Detection Pipeline Dashboard Panels

- **Detection Funnel**: Real-time funnel showing L1 → L2 → L3 progression
- **Model Confidence Distribution**: Histograms per model
- **False Positive/Negative Trends**: Rolling 7-day accuracy metrics
- **Manipulation Type Distribution**: Pie chart of detected manipulation types
- **Model Latency**: Per-model inference time over time
- **Triton Queue Depth**: Per-model queue visualization
- **Ensemble Agreement Rate**: How often models agree on verdict

---

## 6. Deepfake Wave Detection

### 6.1 Anomaly Detection System

The system monitors for coordinated deepfake campaigns ("deepfake waves") using:

**Detection Signals**:
1. **Volume Anomaly**: Detection rate (BLOCK + FLAG) exceeds 3x the rolling 7-day average
2. **Similarity Clustering**: Multiple blocked videos share similar manipulation fingerprints (same GAN model, same face target)
3. **Geographic Concentration**: Detections cluster in specific regions
4. **Temporal Pattern**: Detection rate shows unnatural spikes (bot-like upload patterns)
5. **Target Concentration**: Multiple deepfakes targeting the same public figure

### 6.2 Wave Detection Algorithm

```
Every 5 minutes:
  1. Compute current detection rate (BLOCK + FLAG) per 5-min window
  2. Compare against 7-day rolling average for same time-of-day
  3. If rate > 3x average:
     a. Cluster recent blocked videos by manipulation fingerprint
     b. Cluster by target face (if public figure)
     c. Cluster by source account trust scores
     d. If significant clusters found → WAVE DETECTED

Wave Response:
  1. Alert P2 → Security team
  2. Auto-increase L3 capacity (preemptive scaling)
  3. Generate wave report (affected videos, techniques, targets)
  4. Notify affected platform tenants
  5. Brief compliance team for potential regulatory notification
```

### 6.3 Wave Dashboard

- **Wave Detection Timeline**: Historical view of detected waves
- **Wave Analysis Panel**: Current wave details (if active)
  - Manipulation technique distribution
  - Target analysis (public figures affected)
  - Geographic origin heat map
  - Upload velocity graph
  - Account correlation analysis

---

## 7. Incident Management

### 7.1 Incident Severity Definitions

| Severity | Definition | Examples |
|----------|-----------|---------|
| SEV1 | System-wide outage or data breach | All detection unavailable, biometric data leak |
| SEV2 | Major functionality degraded | L3 down, signing unavailable, single region outage |
| SEV3 | Minor functionality impacted | Elevated error rates, slow dashboard, single tenant affected |
| SEV4 | No user impact, potential risk | Internal monitoring gap, non-critical service degraded |

### 7.2 Incident Response Process

```
Alert Fired → On-Call Acknowledges (< 5 min for P1/P2)
  → Assess Severity
  → Open Incident Channel (#inc-YYYY-MM-DD-title)
  → Assign Roles:
     - Incident Commander (IC): Coordinates response
     - Technical Lead (TL): Drives investigation and fix
     - Communications Lead (CL): Updates status page and stakeholders
  → Investigate and Mitigate
  → Resolve
  → Post-Incident Review (within 48 hours for SEV1/SEV2)
```

### 7.3 Communication Templates

**Status Page Update (outage)**:
```
Title: Elevated latency on Veritas Detection API
Status: Investigating
Time: 2026-03-08 14:23 UTC

We are investigating reports of elevated latency on the
detection API in the EU-Central region. Detection continues
to operate normally in all other regions. We will provide
an update within 30 minutes.
```

**Tenant Notification (compliance incident)**:
```
Subject: Veritas Security Notice - [Incident ID]

Dear [Tenant Name],

We are writing to inform you of a [brief description].
Impact: [specific impact to tenant]
Timeline: [when it started, when detected, when resolved]
Actions taken: [what was done]
Preventive measures: [what will prevent recurrence]

This notice is provided in compliance with our Data
Processing Agreement, Section [X].
```

---

## 8. Runbooks

### 8.1 Runbook Index

| Runbook | Trigger Alert | Document |
|---------|--------------|----------|
| Total System Outage | `VeritasSystemDown` | RB-001 |
| Zero-Retention Failure | `ZeroRetentionViolation` | RB-002 |
| HSM Connectivity Loss | `HSMUnreachable` | RB-003 |
| Kafka Cluster Issues | `KafkaClusterDown` / `KafkaConsumerLagHigh` | RB-004 |
| GPU Node Failure | `GPUUtilizationHigh` / L3 errors | RB-005 |
| Detection Accuracy Drop | `DetectionAccuracyDegradation` | RB-006 |
| Deepfake Wave Response | `DeepfakeWaveDetected` | RB-007 |
| Region Failover | Regional outage detected | RB-008 |
| Certificate Rotation | `CertificateExpiringSoon` | RB-009 |
| Model Rollback | Model serving errors | RB-010 |

### 8.2 Example Runbook: RB-002 Zero-Retention Failure

```
RUNBOOK: RB-002 Zero-Retention Failure
SEVERITY: P1 - Critical
ALERT: ZeroRetentionViolation

CONTEXT:
  The zero-retention verification scanner has detected that
  biometric data may have been persisted to storage. This is a
  GDPR/AI Act compliance violation.

IMMEDIATE ACTIONS (first 5 minutes):
  1. DO NOT PANIC. The detection means our safeguards are working.
  2. Identify the affected node(s):
     - Check: veritas_zero_retention_verified == 0
     - Identify: node name, region, service
  3. Isolate the affected node(s):
     - kubectl cordon <node>
     - kubectl drain <node> --grace-period=0 --force
  4. Preserve evidence:
     - Take memory dump (if safe to do so)
     - Capture pod logs
     - Record timeline

INVESTIGATION (next 30 minutes):
  5. Determine root cause:
     - Was swap accidentally enabled?
     - Did a pod mount a persistent volume?
     - Was a core dump generated?
     - Did logging accidentally capture biometric data?
  6. Assess scope:
     - How many scans were affected?
     - Which tenants were impacted?
     - How long was the condition present?

REMEDIATION:
  7. If data found on disk:
     - Secure delete: shred -n 7 -z <file>
     - Verify deletion
  8. If in container filesystem:
     - Terminate and delete container
     - Delete underlying node disk (create new node)
  9. Document everything

COMPLIANCE NOTIFICATION (required):
  10. Notify DPO within 1 hour
  11. Notify affected tenants within 24 hours (per DPA)
  12. If data breach confirmed: GDPR 72-hour notification to DPA
  13. File compliance incident report

PREVENTION:
  14. Root cause analysis → fix deployed
  15. Add additional verification checks
  16. Update runbook if needed
```

---

## 9. Post-Incident Process

### 9.1 Post-Incident Review (PIR)

Required for all SEV1 and SEV2 incidents. Conducted within 48 hours.

**PIR Template**:
```
Incident ID: INC-2026-0042
Severity: SEV2
Duration: 47 minutes
Impact: L3 detection unavailable in EU-Central

Timeline:
  14:23 UTC - Alert fired: L3InferenceFailureRate
  14:28 UTC - On-call acknowledged
  14:35 UTC - Root cause identified: GPU node OOM due to model memory leak
  14:42 UTC - Mitigation: Rollback to previous model version
  14:55 UTC - L3 inference restored
  15:10 UTC - All-clear confirmed, monitoring normal

Root Cause:
  New model version (ViT v1.4.3) had a memory leak in attention
  map computation. Under sustained load, GPU memory was exhausted
  after ~2 hours of operation.

What Went Well:
  - Alert fired quickly (< 2 min from first error)
  - On-call response was fast
  - Model rollback was smooth (Triton version management)
  - L1+L2 continued to operate (graceful degradation)

What Could Be Improved:
  - Model load testing should include sustained-load memory profiling
  - Need automated memory leak detection in canary deployments

Action Items:
  [ ] Add memory profiling to model validation pipeline (Owner: ML team, Due: 2026-03-22)
  [ ] Implement GPU memory monitoring in canary deployment (Owner: SRE, Due: 2026-03-15)
  [ ] Add Triton memory limit alerts (Owner: SRE, Due: 2026-03-10)
```

### 9.2 Incident Metrics Tracking

| Metric | Target | Current |
|--------|--------|---------|
| MTTD (Mean Time to Detect) | < 2 minutes | - |
| MTTA (Mean Time to Acknowledge) | < 5 minutes | - |
| MTTR (Mean Time to Resolve) | < 30 minutes (SEV1), < 2 hours (SEV2) | - |
| Incidents per month | < 2 SEV1, < 5 SEV2 | - |
| PIR completion rate | 100% for SEV1/SEV2 | - |
| Action item completion rate | > 90% within 30 days | - |
