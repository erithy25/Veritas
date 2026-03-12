#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# Veritas B2B - Kafka Topic Creation Script
# Run after Kafka is healthy: ./scripts/create-kafka-topics.sh
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP:-localhost:9092}"

create_topic() {
    local name=$1
    local partitions=$2
    local retention_ms=$3

    echo "Creating topic: $name (partitions=$partitions, retention=${retention_ms}ms)"
    kafka-topics --bootstrap-server "$KAFKA_BOOTSTRAP" \
        --create --if-not-exists \
        --topic "$name" \
        --partitions "$partitions" \
        --replication-factor 1 \
        --config retention.ms="$retention_ms" \
        --config compression.type=lz4 \
        2>/dev/null || echo "  (topic may already exist)"
}

echo "Creating Veritas Kafka topics on $KAFKA_BOOTSTRAP"
echo "─────────────────────────────────────────────────"

# Ingestion
create_topic "veritas.ingest.raw"          6  3600000       # 1 hour retention

# L1 Processing
create_topic "veritas.l1.results"          6  86400000      # 24 hours

# L2 Processing
create_topic "veritas.l2.queue"            6  3600000       # 1 hour
create_topic "veritas.l2.results"          6  86400000      # 24 hours

# L3 Processing
create_topic "veritas.l3.queue"            3  7200000       # 2 hours
create_topic "veritas.l3.results"          3  86400000      # 24 hours

# Verdicts & Compliance
create_topic "veritas.verdicts"            6  604800000     # 7 days
create_topic "veritas.compliance.events"   3  2592000000    # 30 days
create_topic "veritas.alerts"              3  604800000     # 7 days

echo ""
echo "All topics created. Listing:"
kafka-topics --bootstrap-server "$KAFKA_BOOTSTRAP" --list | grep veritas
