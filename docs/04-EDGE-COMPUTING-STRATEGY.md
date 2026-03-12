# Veritas B2B - Edge Computing Strategy

**Version**: 1.0.0
**Last Updated**: 2026-03-08
**Objective**: Achieve sub-100ms upload latency globally

---

## Table of Contents

1. [Latency Analysis](#1-latency-analysis)
2. [Edge Architecture](#2-edge-architecture)
3. [Edge Node Design](#3-edge-node-design)
4. [Global Routing Strategy](#4-global-routing-strategy)
5. [Edge-to-Cloud Data Flow](#5-edge-to-cloud-data-flow)
6. [Edge Security](#6-edge-security)
7. [Edge Monitoring](#7-edge-monitoring)

---

## 1. Latency Analysis

### 1.1 Latency Budget Breakdown

The target is **< 100ms** from the moment a platform initiates the API call to the moment Veritas acknowledges receipt (not full analysis completion). Full analysis results are delivered asynchronously or within the synchronous response depending on integration mode.

| Phase | Target | Optimization |
|-------|--------|-------------|
| DNS Resolution | < 5ms | Anycast DNS, pre-resolved connections |
| TCP + TLS Handshake | < 15ms | Edge termination, TLS 1.3, 0-RTT resumption |
| HTTP/2 Stream Setup | < 5ms | gRPC multiplexing, persistent connections |
| Request Validation | < 5ms | Edge-local auth token cache |
| Data Transfer (first chunk) | < 20ms | Edge proximity, < 50km to user |
| Edge Processing | < 10ms | L1 pre-screening at edge |
| Queue Acknowledgment | < 10ms | Local Kafka broker or direct forward |
| Response Serialization | < 5ms | Pre-compiled protobuf |
| **Total** | **< 75ms** | **25ms margin for jitter** |

### 1.2 Current Internet Latency by Region

| From | To Nearest Edge | Round-Trip Estimate |
|------|----------------|-------------------|
| San Francisco | US-West Edge (Oregon) | 15-25ms |
| New York | US-East Edge (Virginia) | 10-20ms |
| London | EU-West Edge (Frankfurt) | 15-25ms |
| Tokyo | AP-East Edge (Tokyo) | 5-15ms |
| Singapore | AP-South Edge (Singapore) | 5-15ms |
| Sao Paulo | US-East Edge (Virginia) | 120-150ms |
| Mumbai | AP-South Edge (Singapore) | 40-60ms |
| Lagos | EU-West Edge (Frankfurt) | 100-140ms |

**Problem regions** (> 100ms to nearest analysis cluster): South America, Africa, India, Middle East.
**Solution**: Deploy lightweight edge nodes in these regions.

---

## 2. Edge Architecture

### 2.1 Three-Tier Edge Model

```
Tier 1: CDN Edge PoPs (400+ locations)
  └── TLS termination, request routing, connection pooling

Tier 2: Regional Edge Nodes (15-20 locations)
  └── L1 pre-screening, auth caching, video chunking, queue proxy

Tier 3: Analysis Clusters (6-8 locations)
  └── Full L1/L2/L3 detection, scoring, signing, storage
```

### 2.2 Tier 1 - CDN Edge PoPs

**Technology**: Cloudflare Workers or AWS CloudFront + Lambda@Edge

**Functions**:
- TLS 1.3 termination with 0-RTT session resumption
- Geographic request routing (latency-based DNS)
- Connection multiplexing (pool persistent HTTP/2 connections to Tier 2)
- DDoS absorption and rate limiting (coarse-grained)
- Request size validation (reject oversized uploads early)
- Health check routing (bypass unhealthy Tier 2 nodes)

**Deployment**: Managed CDN service, no custom hardware required.

### 2.3 Tier 2 - Regional Edge Nodes

**Technology**: Kubernetes clusters on lightweight instances (AWS Outposts, GCP Distributed Cloud, or bare-metal colocation)

**Locations** (covering underserved regions):

| Location | Provider | Purpose |
|----------|----------|---------|
| Sao Paulo, Brazil | AWS sa-east-1 | South America coverage |
| Mumbai, India | AWS ap-south-1 | Indian subcontinent |
| Johannesburg, South Africa | Azure South Africa North | Sub-Saharan Africa |
| Dubai, UAE | AWS me-south-1 | Middle East |
| Sydney, Australia | AWS ap-southeast-2 | Oceania |
| Seoul, South Korea | AWS ap-northeast-2 | Korea coverage |
| Warsaw, Poland | GCP europe-central2 | Eastern Europe |
| Toronto, Canada | AWS ca-central-1 | Canada data residency |
| Osaka, Japan | AWS ap-northeast-3 | Japan HA |
| Jakarta, Indonesia | GCP asia-southeast2 | Southeast Asia |

**Functions**:
- **L1 Pre-screening**: Run metadata extraction and hash lookups locally
  - Maintain a synchronized Redis replica with the top 10M most common deepfake hashes
  - If hash matches: return immediate BLOCK without cloud round-trip
  - If clean metadata + no hash match: forward to cloud with "L1-CLEAR" annotation
- **Video Chunking**: Split large uploads into chunks for parallel forwarding
- **Auth Token Cache**: Cache validated JWT tokens (5-minute TTL) to avoid cloud auth round-trip
- **Compression**: Compress frame data before forwarding to analysis cluster
- **Queue Proxy**: Buffer frames to local Kafka proxy, forward to regional analysis cluster

**Hardware per Tier 2 Node**:
- 4x c7g.xlarge (16 vCPU, 32 GB RAM)
- 1x ElastiCache Redis replica (cache.r7g.large, 16 GB)
- 1x Kafka proxy (lightweight, forwards to main cluster)
- Estimated cost: ~$3,000/month per location

### 2.4 Tier 3 - Analysis Clusters

Full analysis capability as described in the System Design Document. Located in:
- US-East (Virginia)
- US-West (Oregon)
- EU-Central (Frankfurt)
- EU-North (Stockholm)
- AP-Northeast (Tokyo)
- AP-Southeast (Singapore)

---

## 3. Edge Node Design

### 3.1 Edge Node Software Stack

```
┌─────────────────────────────────┐
│       Envoy Proxy (L7)          │  ← TLS termination, routing
├─────────────────────────────────┤
│     veritas-edge-gateway        │  ← Auth cache, rate limiting
├─────────────────────────────────┤
│     veritas-edge-l1             │  ← Metadata check, hash lookup
├─────────────────────────────────┤
│     Redis (read replica)        │  ← 10M hash subset
├─────────────────────────────────┤
│     Kafka Proxy (MirrorMaker)   │  ← Queue forwarding
├─────────────────────────────────┤
│     Prometheus Agent            │  ← Metrics collection
└─────────────────────────────────┘
```

### 3.2 Edge Hash Database Synchronization

The edge maintains a subset of the full hash database for fast local lookups:

- **Full database size**: ~100M hashes (in cloud Redis)
- **Edge subset size**: ~10M hashes (most frequently matched + most recent additions)
- **Sync frequency**: Every 60 seconds (delta sync via Redis replication)
- **Sync protocol**: Redis replication stream (encrypted)
- **Fallback**: If hash not in local subset, frame forwarded to cloud for full L1

**Subset Selection Algorithm**:
1. Top 5M most frequently matched hashes (LFU)
2. Top 3M most recently added hashes (LRU)
3. Top 2M region-specific hashes (content trending in this region)

### 3.3 Edge Decision Matrix

| Edge L1 Result | Action | Cloud Processing |
|----------------|--------|-----------------|
| Hash match (exact) | BLOCK immediately | Async notification for audit log |
| Known deepfake tool in metadata | Forward with HIGH priority | Full L1 + L2 + L3 |
| Clean metadata, no hash match | Forward with NORMAL priority | Full L1 + L2 (L3 if needed) |
| Invalid file format | REJECT immediately | None |
| Oversized file | REJECT immediately | None |

---

## 4. Global Routing Strategy

### 4.1 DNS-Based Routing

**Service**: AWS Route 53 or Cloudflare DNS with latency-based routing

**DNS Configuration**:
```
api.veritas.security     → Latency-based routing
  ├── us-east.api.veritas.security    (Virginia)
  ├── us-west.api.veritas.security    (Oregon)
  ├── eu-central.api.veritas.security (Frankfurt)
  ├── eu-north.api.veritas.security   (Stockholm)
  ├── ap-east.api.veritas.security    (Tokyo)
  └── ap-south.api.veritas.security   (Singapore)
```

**Routing Logic**:
1. Client resolves `api.veritas.security`
2. DNS returns IP of nearest healthy edge PoP (Anycast)
3. Edge PoP identifies nearest Tier 2 node
4. Tier 2 node forwards to assigned analysis cluster

### 4.2 Data Residency Routing Override

For EU tenants, DNS routing is overridden to ensure all traffic goes to EU regions:

```
EU Tenant Request → Any Edge PoP → EU-Central or EU-North (only)
                                    ↓
                              Never routed to US/AP clusters
```

This is enforced at the edge gateway level by checking the tenant's `jurisdiction` field from the cached tenant config.

### 4.3 Failover Routing

| Scenario | Behavior |
|----------|----------|
| Edge PoP down | CDN automatically routes to next-nearest PoP |
| Tier 2 node down | Edge PoP routes to next-nearest Tier 2 |
| Analysis cluster down | Tier 2 buffers and routes to secondary cluster |
| Cross-region link down | Tier 2 operates in degraded mode (L1-only) |

**Health Check Configuration**:
- Active health checks every 10 seconds (TCP + HTTP)
- Passive health checks via error rate monitoring
- Failover trigger: 3 consecutive failed health checks or error rate > 5%
- Recovery: Gradual traffic shift (10% → 50% → 100% over 5 minutes)

---

## 5. Edge-to-Cloud Data Flow

### 5.1 Upload Optimization

1. **Chunked Transfer**: Videos split into 1MB chunks at the edge
2. **Parallel Upload**: Up to 8 chunks uploaded simultaneously to analysis cluster
3. **Resumable Upload**: Interrupted uploads resume from last successful chunk
4. **Compression**: Lossless compression (LZ4) of frame data before cloud transfer
5. **Deduplication**: If identical content was analyzed recently (content-addressable hash), return cached result

### 5.2 Connection Pooling

Edge nodes maintain persistent gRPC connections to analysis clusters:
- **Pool size**: 64 connections per Tier 2 node per analysis cluster
- **Keep-alive**: 30-second ping interval
- **Connection lifetime**: 1 hour maximum (then graceful rotation)
- **Protocol**: HTTP/2 multiplexing (up to 1000 concurrent streams per connection)

### 5.3 Bandwidth Optimization

| Technique | Savings | Trade-off |
|-----------|---------|-----------|
| Edge L1 pre-screening | 80-85% of clean content never reaches cloud | Edge compute cost |
| Frame subsampling | 70% bandwidth reduction for long videos | Slight accuracy decrease |
| LZ4 compression | 30-40% reduction on frame data | Minimal CPU overhead |
| Perceptual hash only (no raw frames for L1) | 99.9% reduction for hash-only checks | Cannot support L2/L3 at edge |

---

## 6. Edge Security

### 6.1 Edge Node Hardening

- **OS**: Minimal container-optimized OS (Bottlerocket, Flatcar)
- **Runtime**: gVisor or Kata Containers for additional isolation
- **Network**: No inbound ports except 443 (HTTPS/gRPC)
- **Secrets**: No signing keys at edge (signing only occurs in cloud)
- **Data**: No persistent storage of video content at edge
- **Updates**: Automatic rolling updates from central management

### 6.2 Edge-to-Cloud Security

- All edge-to-cloud traffic encrypted with mTLS (certificate pinning)
- Edge nodes authenticate to cloud using short-lived tokens (1-hour rotation)
- Edge Redis replicas use encrypted replication (TLS)
- No customer data logged at edge (only metrics and error counts)

### 6.3 Anti-Tampering

- Edge node integrity verified every 5 minutes (remote attestation)
- Binary signing ensures only signed code runs on edge nodes
- Immutable root filesystem
- Anomaly detection on edge behavior (unusual traffic patterns trigger alert)

---

## 7. Edge Monitoring

### 7.1 Metrics Collected at Edge

| Metric | Purpose | Alert Threshold |
|--------|---------|----------------|
| `edge_request_latency_ms` | Upload latency measurement | P99 > 80ms |
| `edge_l1_hit_rate` | Edge hash match rate | Deviation > 20% from baseline |
| `edge_to_cloud_latency_ms` | Cloud forwarding latency | P99 > 50ms |
| `edge_connection_pool_available` | Connection pool health | < 10 available connections |
| `edge_redis_sync_lag_seconds` | Hash DB synchronization delay | > 120 seconds |
| `edge_error_rate` | Request error rate | > 1% |
| `edge_bandwidth_mbps` | Network utilization | > 80% capacity |

### 7.2 Edge Dashboards

Each edge node reports to the central Prometheus/Grafana stack:
- **Global Edge Map**: Visual map showing health status of all edge nodes
- **Latency Heatmap**: Geographic latency distribution
- **Edge Hit Rate**: Percentage of requests resolved at edge without cloud round-trip
- **Edge Capacity**: CPU, memory, network utilization per node

### 7.3 Edge SLA

| Metric | Target |
|--------|--------|
| Edge availability | 99.99% |
| Edge-to-client latency (P50) | < 30ms |
| Edge-to-client latency (P99) | < 80ms |
| Edge L1 pre-screening rate | > 80% of all uploads |
| Hash DB sync freshness | < 60 seconds |
