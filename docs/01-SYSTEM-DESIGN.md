# Veritas B2B - System Design Document

**Version**: 1.0.0
**Classification**: Confidential - Internal
**Last Updated**: 2026-03-08

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Overview](#2-system-overview)
3. [Architecture Principles](#3-architecture-principles)
4. [Component Architecture](#4-component-architecture)
5. [High-Speed Ingestion Layer](#5-high-speed-ingestion-layer)
6. [Multi-Stage Detection Engine](#6-multi-stage-detection-engine)
7. [Risk Scoring & Policy Engine](#7-risk-scoring--policy-engine)
8. [Security & Compliance Layer](#8-security--compliance-layer)
9. [Explainable AI Engine](#9-explainable-ai-engine)
10. [Inter-Service Communication](#10-inter-service-communication)
11. [Failure Modes & Resilience](#11-failure-modes--resilience)
12. [Performance Budgets](#12-performance-budgets)
13. [Multi-Tenancy Architecture](#13-multi-tenancy-architecture)

---

## 1. Executive Summary

Veritas B2B is an enterprise-grade deepfake detection middleware designed for inline integration with social media platform content upload pipelines. The system operates as a synchronous and asynchronous content gatekeeper, providing three-tier media analysis with cryptographically verifiable results.

**Core Problem**: Social media platforms process billions of video uploads daily. Current content moderation systems lack specialized deepfake detection capabilities that can operate at platform scale while meeting emerging regulatory requirements (EU AI Act, DSA).

**Solution**: A horizontally scalable middleware that integrates via gRPC into existing upload pipelines, providing sub-second detection results for 95% of content (L1/L2) and deferred analysis for complex cases (L3), with full audit trails and cryptographic evidence chains.

**Target Throughput**: 1M+ concurrent video analysis sessions, with peak capacity of 50M requests/hour.

---

## 2. System Overview

### 2.1 System Boundaries

Veritas operates between the platform's upload endpoint and its content delivery pipeline:

```
Platform Upload CDN → [Veritas Edge Proxy] → [Veritas Analysis Cloud] → Decision → Platform Pipeline
```

### 2.2 Integration Model

Veritas supports two integration modes:

1. **Synchronous (Inline)**: The platform's upload pipeline calls Veritas and waits for a verdict before publishing content. Used for platforms requiring pre-publication review.

2. **Asynchronous (Sidecar)**: The platform publishes content immediately and submits it to Veritas in parallel. Veritas delivers verdicts via webhook or streaming gRPC. Used for platforms that prioritize upload speed and handle takedowns post-publication.

### 2.3 Core Functional Requirements

| Requirement | Target |
|-------------|--------|
| End-to-end latency (L1+L2) | < 200ms for 720p video |
| End-to-end latency (L1+L2+L3) | < 2s for 720p video |
| Throughput per node | 10,000 requests/second |
| False Positive Rate | < 0.01% |
| False Negative Rate | < 0.1% |
| Availability | 99.99% (52.6 min downtime/year) |
| Data retention (biometric) | 0 seconds (in-memory only) |
| Signature validity | 10 years (archival grade) |

---

## 3. Architecture Principles

### 3.1 Design Tenets

1. **Defense in Depth**: Every layer validates input independently. No layer trusts upstream results implicitly.
2. **Compute Proportional to Risk**: The three-tier detection model ensures expensive GPU inference is only triggered when cheaper heuristics are insufficient.
3. **Privacy by Architecture**: Biometric data never leaves RAM. The system is designed so that persistent storage of biometric vectors is architecturally impossible, not just policy-prohibited.
4. **Cryptographic Non-Repudiation**: Every detection result carries a digital signature chain that can be independently verified without access to Veritas systems.
5. **Regulatory Determinism**: The system's behavior must be fully auditable and reproducible. Given the same input and model version, the system must produce identical results.
6. **Graceful Degradation**: Under extreme load, the system degrades from L3 to L2 to L1 analysis rather than dropping requests.
7. **Multi-Tenancy Isolation**: Each platform customer operates in a logically isolated environment with independent policy configurations.

### 3.2 Tech Stack Rationale

| Decision | Choice | Rationale |
|----------|--------|-----------|
| API Layer Language | Rust | Zero-cost abstractions, memory safety without GC pauses, predictable latency. Tonic framework for gRPC provides native async I/O. |
| ML Pipeline Language | Python | Ecosystem dominance for ML (PyTorch, TensorFlow). NVIDIA Triton provides a language-agnostic inference server, minimizing Python's performance impact. |
| Message Broker | Apache Kafka | Log-based architecture enables replay for debugging and reprocessing. Partitioned topics provide natural sharding per customer. |
| Primary DB (Analytics) | ClickHouse | Column-oriented storage provides 100x compression and sub-second analytical queries over billions of log entries. |
| Primary DB (Signatures) | PostgreSQL + TimescaleDB | ACID compliance for cryptographic evidence. TimescaleDB extension for time-series queries on scan history. |
| Cache Layer | Redis Cluster | Sub-millisecond reads for hash lookups (L1). Pub/Sub for real-time dashboard updates. |
| Model Serving | NVIDIA Triton | Multi-framework support (PyTorch, TensorFlow, ONNX), dynamic batching, model versioning, GPU sharing. |
| Orchestration | Kubernetes | Industry standard for container orchestration. HPA/VPA for autoscaling. Multi-cloud portability. |

---

## 4. Component Architecture

### 4.1 Logical Components

The system is decomposed into the following microservices:

```
veritas-gateway          - Rust gRPC/REST API gateway, TLS termination, auth, rate limiting
veritas-ingest           - Rust video frame extraction, format normalization, queue dispatch
veritas-l1-scanner       - Rust metadata parser, hash computation, database lookup
veritas-l2-biometric     - Python biometric inconsistency analysis (RPPG, micro-flickering)
veritas-l3-deepnet       - Python/Triton deep neural network inference orchestrator
veritas-scorer           - Rust risk scoring engine, policy evaluation
veritas-signer           - Rust cryptographic signature service (HSM-backed)
veritas-dashboard        - TypeScript/React moderator dashboard
veritas-compliance       - Rust EU AI Act reporting, C2PA metadata generation
veritas-reporter         - Python automated regulatory report generation
veritas-redteam-sandbox  - Isolated adversarial testing environment
```

### 4.2 Service Ownership Matrix

| Service | Team | Language | GPU Required | Stateful |
|---------|------|----------|-------------|----------|
| veritas-gateway | Platform Team | Rust | No | No |
| veritas-ingest | Platform Team | Rust | No | No |
| veritas-l1-scanner | Detection Team | Rust | No | No (reads Redis/DB) |
| veritas-l2-biometric | ML Team | Python | Yes (optional) | No |
| veritas-l3-deepnet | ML Team | Python | Yes | No |
| veritas-scorer | Detection Team | Rust | No | No |
| veritas-signer | Security Team | Rust | No | Yes (HSM) |
| veritas-dashboard | Frontend Team | TypeScript | No | No |
| veritas-compliance | Compliance Team | Rust | No | Yes (DB) |
| veritas-reporter | Compliance Team | Python | No | Yes (DB) |
| veritas-redteam-sandbox | Security Team | Mixed | Yes | Yes (isolated) |

---

## 5. High-Speed Ingestion Layer

### 5.1 API Gateway (veritas-gateway)

The gateway is the single entry point for all platform traffic. It is implemented in Rust using the `tonic` gRPC framework with `axum` for REST compatibility.

**Responsibilities**:
- mTLS termination and client certificate validation
- API key and JWT authentication per tenant
- Request validation and schema enforcement
- Rate limiting (per-tenant, per-endpoint)
- Request routing (sync vs async path)
- Load shedding under extreme pressure
- Request/response logging (non-biometric fields only)

**Connection Management**:
- HTTP/2 multiplexing for gRPC (unlimited concurrent streams per connection)
- Connection pooling with configurable limits per upstream service
- Backpressure propagation via gRPC flow control

**Authentication Flow**:
```
Client → mTLS Handshake → Certificate Validation → JWT Extraction →
Tenant Resolution → Rate Limit Check → Schema Validation → Route to Service
```

### 5.2 Video Ingestion Service (veritas-ingest)

This service receives raw video data and prepares it for analysis.

**Processing Pipeline**:
1. **Format Detection**: Identify container format (MP4, WebM, MKV, MOV, AVI) and codec (H.264, H.265, VP9, AV1)
2. **Integrity Check**: Verify file is not truncated or corrupted (checksum validation)
3. **Frame Extraction**: Decode key frames at configurable intervals (default: 1 frame/second for videos > 10s, all frames for videos < 10s)
4. **Face Detection**: Run lightweight face detection (MTCNN or RetinaFace) to identify regions of interest
5. **Normalization**: Resize face crops to 224x224 (model input size), normalize color space to sRGB
6. **Queue Dispatch**: Publish normalized frame batches to Kafka topic partitioned by tenant

**Optimization Strategies**:
- Hardware-accelerated decoding via NVDEC (NVIDIA) or VAAPI (Intel)
- Parallel frame extraction across CPU cores using Rayon (Rust)
- Zero-copy frame passing between decode and normalization stages
- Adaptive frame sampling: more frames for face-containing segments, fewer for static scenes

### 5.3 Message Queue Architecture (Apache Kafka)

**Topic Design**:

| Topic | Partitions | Retention | Purpose |
|-------|-----------|-----------|---------|
| `veritas.ingest.raw` | 256 | 1 hour | Raw frame batches awaiting L1 |
| `veritas.l1.results` | 128 | 24 hours | L1 scan results |
| `veritas.l2.queue` | 128 | 1 hour | Frames requiring L2 analysis |
| `veritas.l2.results` | 128 | 24 hours | L2 scan results |
| `veritas.l3.queue` | 64 | 2 hours | Frames requiring L3 analysis |
| `veritas.l3.results` | 64 | 24 hours | L3 scan results |
| `veritas.verdicts` | 256 | 7 days | Final verdicts for audit trail |
| `veritas.compliance.events` | 32 | 30 days | Compliance-relevant events |
| `veritas.alerts` | 16 | 7 days | System alerts and anomalies |

**Partitioning Strategy**: Messages are partitioned by `tenant_id + upload_id` to ensure all frames from a single video are processed by the same consumer (maintaining ordering guarantees within a video).

**Consumer Group Design**:
- Each detection tier (L1, L2, L3) runs as an independent consumer group
- Consumer groups scale independently based on queue depth
- Dead letter queues capture messages that fail processing after 3 retries

---

## 6. Multi-Stage Detection Engine

### 6.1 Detection Philosophy

The three-tier design follows a "filter funnel" pattern:

```
100% of uploads → L1 (fast, cheap)    → 15-20% flagged → L2 (medium, moderate cost)
→ 3-5% flagged  → L3 (slow, expensive) → 0.5-1% blocked
```

This approach reduces GPU costs by ~95% compared to running deep neural network analysis on all uploads.

### 6.2 L1 - Metadata & Hash Check (veritas-l1-scanner)

**Implementation Language**: Rust
**Average Latency**: < 5ms per video
**GPU Required**: No

**Analysis Techniques**:

1. **Perceptual Hash Matching**:
   - Compute pHash, dHash, and aHash of extracted frames
   - Query Redis for matches against a known deepfake database (100M+ entries)
   - Similarity threshold: Hamming distance < 8 bits (configurable per tenant)
   - Database updated continuously from partner feeds (academic institutions, government agencies)

2. **Metadata Forensics**:
   - Parse EXIF, XMP, and container-level metadata
   - Detect editing software signatures (Adobe After Effects, FaceSwap, DeepFaceLab, etc.)
   - Identify inconsistent creation/modification timestamps
   - Check for stripped or tampered GPS/device information
   - Verify codec parameters match claimed recording device

3. **C2PA/Content Credentials Validation**:
   - If content carries C2PA manifests, validate the signature chain
   - Cross-reference content credentials with known signing authorities
   - Flag content with broken or missing credential chains

4. **Statistical Anomaly Detection**:
   - Frame-level entropy analysis (deepfakes often show abnormal compression patterns)
   - GOP (Group of Pictures) structure analysis for re-encoding detection
   - Bitrate consistency check (spliced content shows bitrate discontinuities)

**L1 Decision Matrix**:

| Signal | Action |
|--------|--------|
| Exact hash match in deepfake DB | → BLOCK (skip L2/L3) |
| Known deepfake tool in metadata | → Escalate to L2 with HIGH priority |
| Suspicious compression patterns | → Escalate to L2 with MEDIUM priority |
| Valid C2PA chain, no anomalies | → ALLOW (skip L2/L3) |
| No signals detected | → Escalate to L2 with LOW priority |

### 6.3 L2 - Biometric Inconsistency Scan (veritas-l2-biometric)

**Implementation Language**: Python
**Average Latency**: 50-150ms per face region
**GPU Required**: Optional (CPU fallback available)

**Analysis Techniques**:

1. **Micro-Flickering Detection**:
   - Analyze temporal consistency of face boundaries across consecutive frames
   - Deepfake face swaps produce sub-pixel boundary oscillations at face edges
   - Fourier transform of boundary positions reveals non-natural frequency patterns
   - Threshold: Boundary oscillation amplitude > 0.3px at frequencies > 15Hz

2. **Remote Photoplethysmography (rPPG) Analysis**:
   - Extract subtle color changes in facial skin caused by blood flow
   - Real faces show periodic signals (60-100 BPM) correlating with heartbeat
   - GAN-generated faces lack physiologically plausible rPPG signals
   - Analysis requires minimum 2 seconds of video (60 frames at 30fps)
   - Signal quality validation: SNR > 3dB required for conclusive result

3. **Eye Movement Analysis (Oculomotor Consistency)**:
   - Track pupil position and iris reflection across frames
   - Natural eye movements follow predictable saccade-fixation patterns
   - Current deepfake models produce statistically abnormal eye movement distributions
   - Measure blink rate (natural: 15-20 blinks/minute) and blink duration
   - Corneal light reflection consistency check (Purkinje images)

4. **Facial Symmetry & Geometry**:
   - 68-point facial landmark tracking
   - Measure bilateral symmetry deviations (deepfakes often have asymmetric artifacts)
   - Jaw-to-face proportion analysis
   - Ear-to-nose alignment consistency

5. **Skin Texture Analysis**:
   - Pore-level texture frequency analysis
   - GAN artifacts produce characteristic high-frequency patterns
   - Noise residual extraction using SRM (Spatial Rich Model) filters
   - Texture consistency between face and neck/ear regions

**L2 Decision Matrix**:

| Findings | Action |
|----------|--------|
| rPPG absent + micro-flickering detected | → BLOCK (high confidence) |
| 2+ biometric inconsistencies | → Escalate to L3 with HIGH priority |
| 1 biometric inconsistency | → Escalate to L3 with MEDIUM priority |
| All biometric checks pass | → ALLOW |

### 6.4 L3 - Deep Neural Network Analysis (veritas-l3-deepnet)

**Implementation Language**: Python (model orchestration) + NVIDIA Triton (inference)
**Average Latency**: 200ms - 2s per video
**GPU Required**: Yes (NVIDIA A100/H100)

**Model Ensemble Architecture**:

The L3 tier employs an ensemble of specialized models, each targeting different deepfake generation techniques:

1. **Vision Transformer (ViT-L/16) - General Purpose**:
   - Pre-trained on ImageNet, fine-tuned on FaceForensics++, DFDC, and proprietary datasets
   - Input: 224x224 face crops
   - Detects broad spectrum of face manipulation artifacts
   - Attention maps provide spatial localization of detected artifacts

2. **EfficientNet-B7 - GAN Artifact Detector**:
   - Specialized for detecting GAN-specific frequency domain artifacts
   - Trained on StyleGAN, StyleGAN2, StyleGAN3, ProGAN outputs
   - Spectral analysis branch detects characteristic GAN "fingerprints"

3. **Temporal Consistency Network (TCN)**:
   - 3D ConvNet analyzing temporal coherence across frame sequences
   - Detects inter-frame inconsistencies invisible in single-frame analysis
   - Input: 16-frame sequences at native resolution
   - Specialized for face-swap detection (DeepFaceLab, FaceSwap, etc.)

4. **Diffusion Artifact Detector (DAD)**:
   - Designed specifically for Stable Diffusion, DALL-E, Midjourney outputs
   - Analyzes noise scheduling artifacts unique to diffusion models
   - Continuously retrained as new diffusion architectures emerge

5. **Audio-Visual Sync Analyzer**:
   - Lip-sync analysis using SyncNet architecture
   - Detects dubbed/synthesized speech by measuring audio-visual correlation
   - Phoneme-viseme mapping validation
   - Voice deepfake detection via speaker embedding analysis

**Ensemble Aggregation**:
- Each model produces an independent confidence score [0.0, 1.0]
- Weighted aggregation based on model specialty and input characteristics
- Disagreement between models triggers additional analysis
- Final ensemble score feeds into the Risk Scoring Engine

**Model Lifecycle Management**:
- Models served via NVIDIA Triton Inference Server
- A/B testing of model versions with shadow deployment
- Automated retraining pipeline triggered by performance degradation
- Model versioning tied to detection results for reproducibility
- Canary deployments with automatic rollback on accuracy regression

---

## 7. Risk Scoring & Policy Engine

### 7.1 Scoring Algorithm (veritas-scorer)

The scorer combines detection signals with contextual information to produce a final risk assessment.

**Input Signals**:

| Signal | Weight Range | Source |
|--------|-------------|--------|
| L1 hash match confidence | 0.0 - 1.0 | L1 Scanner |
| L1 metadata anomaly score | 0.0 - 1.0 | L1 Scanner |
| L2 biometric inconsistency count | 0 - 5 | L2 Biometric |
| L2 rPPG signal quality | 0.0 - 1.0 | L2 Biometric |
| L3 ensemble confidence | 0.0 - 1.0 | L3 DeepNet |
| L3 model agreement ratio | 0.0 - 1.0 | L3 DeepNet |
| Public figure match | Boolean | Face recognition DB |
| Political context indicators | 0.0 - 1.0 | NLP analysis of metadata/captions |
| Account trust score | 0.0 - 1.0 | Platform-provided |
| Upload volume anomaly | 0.0 - 1.0 | Internal analytics |

**Scoring Formula**:

```
base_score = Σ(signal_i × weight_i) / Σ(weight_i)

context_multiplier = 1.0
  + (public_figure_detected ? 0.3 : 0.0)
  + (political_context × 0.2)
  + (account_trust_anomaly × 0.15)

final_score = min(1.0, base_score × context_multiplier)
```

### 7.2 Policy Engine

The policy engine maps scores to actions based on tenant-specific configurations.

**Default Policy Thresholds**:

| Score Range | Action | Description |
|-------------|--------|-------------|
| 0.00 - 0.30 | `ALLOW` | Content passes all checks |
| 0.31 - 0.60 | `FLAG` | Content published but flagged for human review |
| 0.61 - 0.85 | `FLAG_URGENT` | Content held, human review required within 1 hour |
| 0.86 - 1.00 | `BLOCK` | Content blocked, creator notified with reason code |

**Tenant-Configurable Parameters**:
- Custom threshold values per action
- Override rules for specific content categories
- Allowlist/blocklist for specific accounts or content creators
- Geographic policy variations (stricter thresholds for election periods)
- Time-based policies (elevated sensitivity during breaking news events)

### 7.3 Moderator Dashboard (veritas-dashboard)

**Technology**: React + TypeScript, WebSocket real-time updates, Recharts for visualization

**Key Features**:

1. **Real-Time Feed**: Live stream of flagged content with detection details
2. **Decision Detail View**: For each flagged video:
   - Original video playback with artifact overlay
   - Heatmap visualization of detected manipulations
   - Per-model confidence breakdown
   - XAI reason codes with natural language explanations
   - rPPG signal visualization (waveform overlay)
   - Side-by-side comparison with source material (if identified)
3. **Analytics Dashboard**:
   - Detection volume over time (by tier, by action)
   - False positive/negative tracking
   - Model accuracy trends
   - Top manipulation techniques (trending)
   - Geographic distribution of detections
4. **Policy Management UI**:
   - Visual threshold editor
   - Policy simulation (test thresholds against historical data)
   - Audit log of policy changes
5. **Human Override Interface**:
   - One-click override with mandatory reason field
   - Escalation workflow for uncertain cases
   - Bulk review capabilities for high-volume events

---

## 8. Security & Compliance Layer

### 8.1 Cryptographic Signature Service (veritas-signer)

**Architecture**: Dedicated microservice with exclusive HSM access

**Signing Process**:
1. Detection result arrives from scorer
2. Canonical JSON serialization of the result (deterministic field ordering)
3. SHA-512 hash of canonical representation
4. Ed25519 signature using HSM-stored private key
5. Signature, public key reference, and timestamp appended to result
6. Signed result published to `veritas.verdicts` topic

**Key Management**:
- Private keys stored in FIPS 140-2 Level 3 Hardware Security Modules (HSM)
- AWS CloudHSM or Azure Dedicated HSM (never software keys in production)
- Key rotation every 90 days with 10-year signature validity
- Dual-key architecture: primary + disaster recovery key pair
- Key ceremony procedure with M-of-N secret sharing for key generation

**Signature Verification**:
- Public keys published at `/.well-known/veritas-keys.json` (RFC 7517 JWK format)
- Third parties can verify signatures without Veritas API access
- Certificate chain anchored to a trusted CA for external verification
- OCSP responder for real-time key revocation checking

### 8.2 Zero-Retention Architecture

**Biometric Data Lifecycle**:

```
Frame received → Extract face crops (RAM) → Biometric analysis (RAM) →
Score generated (RAM) → Biometric data zeroed (secure_memzero) →
Only score + metadata persisted
```

**Technical Enforcement**:
- All biometric processing occurs in tmpfs-backed memory (never touches disk)
- Kubernetes pods running biometric analysis mount no persistent volumes
- Container runtime configured with `--read-only` filesystem
- Memory is explicitly zeroed after use via `secure_memzero()` (not just freed)
- Swap disabled on all nodes processing biometric data (`swapoff -a`)
- Core dumps disabled (`ulimit -c 0`, `/proc/sys/kernel/core_pattern` set to `/dev/null`)
- No network egress from biometric processing pods except to scorer service

**Audit Verification**:
- Automated compliance scanner verifies zero-retention invariants every 5 minutes
- Any biometric data detected in persistent storage triggers immediate alert
- Canary data injected periodically to verify deletion pipeline

---

## 9. Explainable AI Engine

### 9.1 Reason Code System

Every `FLAG` or `BLOCK` decision includes machine-readable reason codes and human-readable explanations.

**Reason Code Taxonomy**:

| Code | Category | Example Explanation |
|------|----------|-------------------|
| `META_TOOL_DETECTED` | L1 - Metadata | "File metadata contains DeepFaceLab v0.12 editing signature" |
| `META_TIMESTAMP_MISMATCH` | L1 - Metadata | "File creation timestamp predates claimed recording device release" |
| `HASH_KNOWN_DEEPFAKE` | L1 - Hash | "Content matches known deepfake (database ID: DF-2026-44821)" |
| `BIO_RPPG_ABSENT` | L2 - Biometric | "No physiologically plausible blood flow signal detected in facial region" |
| `BIO_FLICKER_DETECTED` | L2 - Biometric | "Sub-pixel boundary oscillation detected at face edges (17.3Hz, 0.8px amplitude)" |
| `BIO_EYE_ANOMALY` | L2 - Biometric | "Blink rate (2.1/min) significantly below physiological normal (15-20/min)" |
| `BIO_RPPG_SYNC_FAIL` | L2 - Biometric | "Blood flow signals in left and right cheek are anti-correlated (r=-0.7)" |
| `DNN_GAN_ARTIFACT` | L3 - Neural | "GAN frequency fingerprint detected (StyleGAN2 signature, 94% match)" |
| `DNN_DIFFUSION_ARTIFACT` | L3 - Neural | "Diffusion model noise scheduling artifact detected in skin texture" |
| `DNN_TEMPORAL_INCONSIST` | L3 - Neural | "Inter-frame face geometry varies beyond natural range (3.2x std deviation)" |
| `DNN_LIPSYNC_MISMATCH` | L3 - Neural | "Audio-visual phoneme correlation below threshold (0.23 vs 0.70 expected)" |
| `CTX_PUBLIC_FIGURE` | Context | "Face matches known public figure (confidence: 99.2%)" |
| `CTX_POLITICAL_CONTENT` | Context | "Content classified as political (election-related) with manipulated face" |

### 9.2 Visual Explanation Generation

For each detection, the system generates:
- **Artifact Heatmap**: Pixel-level overlay showing where manipulation was detected
- **Attention Map**: Which regions the neural network focused on for its decision
- **Temporal Graph**: Frame-by-frame confidence scores showing where manipulation starts/stops
- **Comparison Panel**: Original source material (if found) alongside uploaded content

### 9.3 DSA Appeal Support

When a content creator appeals a block decision, the XAI engine provides:
1. Complete reason code list with human-readable explanations in the creator's language
2. Confidence scores for each detection signal
3. Reference to the specific model versions used
4. Link to the cryptographically signed analysis result
5. Instructions for requesting independent third-party verification

---

## 10. Inter-Service Communication

### 10.1 Internal Protocol

All internal service communication uses gRPC with Protocol Buffers v3.

**Service Mesh**: Istio with mTLS for all inter-service communication.

**Circuit Breaker Configuration**:
| Service | Timeout | Retry Count | Circuit Break Threshold |
|---------|---------|-------------|----------------------|
| L1 Scanner | 50ms | 2 | 5 failures in 10s |
| L2 Biometric | 500ms | 1 | 3 failures in 10s |
| L3 DeepNet | 5s | 1 | 3 failures in 30s |
| Scorer | 100ms | 2 | 5 failures in 10s |
| Signer | 200ms | 3 | 2 failures in 10s |

### 10.2 Event-Driven Architecture

Kafka Streams processes real-time analytics:
- Detection rate aggregation (per tenant, per tier, per minute)
- Anomaly detection on detection patterns (deepfake wave early warning)
- Real-time dashboard metric computation
- Compliance event materialization

---

## 11. Failure Modes & Resilience

### 11.1 Degradation Hierarchy

| Scenario | Behavior | SLA Impact |
|----------|----------|------------|
| L3 unavailable | Skip L3, decide on L1+L2 only | Reduced accuracy, maintained throughput |
| L2 unavailable | Skip L2, conservative L1-only decisions | Higher false positive rate |
| L1 unavailable | Queue backpressure, retry with exponential backoff | Increased latency |
| Kafka unavailable | Fallback to in-memory queue (bounded) | Reduced throughput, no replay |
| Redis unavailable | Bypass hash cache, all content goes to L2 | Increased GPU load |
| HSM unavailable | Queue signatures, process in batch on recovery | Delayed signature, detection unaffected |
| Full system overload | Load shedding: reject lowest-priority requests | Partial availability |

### 11.2 Data Consistency

- **Detection results**: At-least-once delivery via Kafka consumer offsets
- **Signatures**: Exactly-once via idempotent signature generation (hash-based dedup)
- **Verdicts**: Immutable append-only log in ClickHouse (no updates, no deletes)

---

## 12. Performance Budgets

### 12.1 Latency Budget (Synchronous Path, 720p Video, 30s)

| Stage | Budget | Cumulative |
|-------|--------|------------|
| TLS/Auth | 5ms | 5ms |
| Frame extraction (10 key frames) | 20ms | 25ms |
| Face detection | 10ms | 35ms |
| L1 Hash + Metadata | 5ms | 40ms |
| Kafka publish + consume | 10ms | 50ms |
| L2 Biometric (per face) | 80ms | 130ms |
| L3 Neural (if needed) | 800ms | 930ms |
| Scoring + Policy | 5ms | 935ms |
| Signing | 10ms | 945ms |
| Response serialization | 5ms | 950ms |
| **Total (with L3)** | | **~950ms** |
| **Total (without L3)** | | **~150ms** |

### 12.2 Resource Budget per 10,000 RPS

| Resource | Quantity | Specification |
|----------|----------|---------------|
| Gateway pods | 4 | 4 vCPU, 8 GB RAM |
| Ingest pods | 8 | 8 vCPU, 16 GB RAM, NVDEC GPU optional |
| L1 Scanner pods | 4 | 4 vCPU, 8 GB RAM |
| L2 Biometric pods | 6 | 8 vCPU, 32 GB RAM, optional T4 GPU |
| L3 DeepNet pods | 4 | 8 vCPU, 64 GB RAM, A100 80GB GPU |
| Kafka brokers | 6 | 8 vCPU, 64 GB RAM, NVMe SSD |
| Redis nodes | 6 | 4 vCPU, 64 GB RAM |
| ClickHouse nodes | 3 | 16 vCPU, 128 GB RAM, NVMe SSD |
| PostgreSQL nodes | 3 | 8 vCPU, 32 GB RAM, SSD |

---

## 13. Multi-Tenancy Architecture

### 13.1 Isolation Model

Veritas uses **logical isolation** with tenant-aware components:

- **Network**: Tenant traffic isolated via Kafka topic partitioning and service mesh policies
- **Compute**: Shared compute pools with per-tenant resource quotas (CPU/GPU/memory limits)
- **Data**: Tenant-specific database schemas in ClickHouse; row-level security in PostgreSQL
- **Policy**: Each tenant has an independent policy configuration stored in PostgreSQL
- **Keys**: Each tenant has dedicated signing key pairs in the HSM

### 13.2 Tenant Onboarding

1. Provision tenant record in PostgreSQL (ID, name, API credentials)
2. Generate tenant-specific signing keys in HSM
3. Create Kafka topic partitions allocated to tenant
4. Initialize ClickHouse schema for tenant
5. Configure default policy thresholds
6. Issue mTLS client certificate
7. Provision rate limit quotas
8. Enable monitoring dashboards

### 13.3 Tenant Configuration Schema

```
Tenant {
  id: UUID
  name: String
  api_key_hash: String
  mtls_cert_fingerprint: String

  policy: {
    allow_threshold: Float (default: 0.30)
    flag_threshold: Float (default: 0.60)
    flag_urgent_threshold: Float (default: 0.85)
    block_threshold: Float (default: 0.86)
    enable_l3: Boolean (default: true)
    max_video_duration_seconds: Int (default: 600)
    max_resolution: String (default: "4K")
    custom_rules: [PolicyRule]
  }

  rate_limits: {
    requests_per_second: Int
    requests_per_day: Int
    concurrent_l3_analyses: Int
  }

  compliance: {
    jurisdiction: String (e.g., "EU", "US", "GLOBAL")
    c2pa_enabled: Boolean
    report_frequency: String (e.g., "MONTHLY")
    data_residency: String (e.g., "eu-west-1")
  }
}
```
