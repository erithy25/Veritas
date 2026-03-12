# Veritas B2B - Implementation Roadmap

**Version**: 1.0.0
**Last Updated**: 2026-03-08
**Estimated Total Duration**: 9-12 months to production-ready

---

## Table of Contents

1. [Phase Overview](#1-phase-overview)
2. [Phase 1: Foundation (Months 1-2)](#2-phase-1-foundation)
3. [Phase 2: Core Detection Engine (Months 2-4)](#3-phase-2-core-detection-engine)
4. [Phase 3: Intelligence Layer (Months 4-6)](#4-phase-3-intelligence-layer)
5. [Phase 4: Compliance & Security (Months 5-7)](#5-phase-4-compliance--security)
6. [Phase 5: Dashboard & Integration (Months 6-8)](#6-phase-5-dashboard--integration)
7. [Phase 6: Scaling & Performance (Months 7-9)](#7-phase-6-scaling--performance)
8. [Phase 7: Production Hardening (Months 9-11)](#8-phase-7-production-hardening)
9. [Phase 8: Launch & Operations (Months 11-12)](#9-phase-8-launch--operations)
10. [Team Structure](#10-team-structure)
11. [Risk Register](#11-risk-register)
12. [Technology Prerequisites](#12-technology-prerequisites)

---

## 1. Phase Overview

```
Month:  1    2    3    4    5    6    7    8    9   10   11   12
        ├────┤    │    │    │    │    │    │    │    │    │    │
Phase 1 ██████████│    │    │    │    │    │    │    │    │    │
Phase 2      │████████████████│    │    │    │    │    │    │    │
Phase 3      │    │    │████████████████│    │    │    │    │    │
Phase 4      │    │    │    │████████████████│    │    │    │    │
Phase 5      │    │    │    │    │████████████████│    │    │    │
Phase 6      │    │    │    │    │    │████████████████│    │    │
Phase 7      │    │    │    │    │    │    │    │████████████│    │
Phase 8      │    │    │    │    │    │    │    │    │    │████████│
```

---

## 2. Phase 1: Foundation (Months 1-2)

### 2.1 Backend Setup

**Task 1.1: Repository & CI/CD Setup**
- Initialize monorepo structure with workspace management
- Configure Rust workspace (Cargo.toml) for shared dependencies
- Configure Python environment (Poetry/uv) for ML services
- Set up CI/CD pipeline (GitHub Actions or GitLab CI):
  - Rust: `cargo check`, `cargo test`, `cargo clippy`, `cargo fmt`
  - Python: `pytest`, `ruff`, `mypy`
  - Container builds (multi-stage Dockerfiles)
  - Security scanning (Trivy, cargo-audit, pip-audit)
- Configure development environments (devcontainer, Nix flake)

**Task 1.2: gRPC API Definition**
- Define Protocol Buffer schemas for all service interfaces:
  - `veritas/api/v1/gateway.proto` (external API)
  - `veritas/internal/v1/ingest.proto` (internal ingestion)
  - `veritas/internal/v1/detection.proto` (L1/L2/L3 interfaces)
  - `veritas/internal/v1/scoring.proto` (scorer interface)
  - `veritas/internal/v1/signing.proto` (signer interface)
  - `veritas/api/v1/dashboard.proto` (dashboard API)
- Generate Rust bindings (tonic-build)
- Generate Python bindings (grpcio-tools)
- Set up protobuf linting (buf)
- Define gRPC error codes and status mapping

**Task 1.3: Infrastructure Provisioning**
- Set up Terraform/OpenTofu modules for:
  - VPC with subnet architecture (as per Cloud Infrastructure doc)
  - EKS/GKE cluster with node pools (CPU + GPU)
  - MSK (Kafka) cluster with topic configuration
  - ElastiCache (Redis) cluster
  - RDS PostgreSQL with TimescaleDB extension
  - ClickHouse cluster on EC2
  - CloudHSM cluster
  - S3 buckets for models and archives
- Configure Kubernetes:
  - Namespaces (production, staging, sandbox)
  - NetworkPolicies
  - ResourceQuotas
  - PodSecurityPolicies/Standards
  - Istio service mesh
- Set up DNS and certificate management

**Task 1.4: Kafka Topic Architecture**
- Create all topics with configured partitions and retention
- Set up Schema Registry for Protobuf/Avro schema validation
- Configure consumer group management
- Implement dead letter queue handling
- Set up Kafka Connect for ClickHouse sink
- Performance test Kafka cluster (target: 100K msgs/sec per broker)

**Milestone**: Infrastructure deployed, gRPC contracts defined, CI/CD pipeline operational.

---

## 3. Phase 2: Core Detection Engine (Months 2-4)

### 3.1 Ingestion Service (veritas-ingest)

**Task 2.1: Video Frame Extraction**
- Implement video container parsing (MP4, WebM, MKV, MOV)
- Integrate FFmpeg (via Rust bindings) for frame extraction
- Implement keyframe-based sampling strategy
- Add hardware-accelerated decoding (NVDEC/VAAPI) support
- Build frame normalization pipeline (resize, color space)
- Implement face detection integration (MTCNN via ONNX Runtime)
- Write comprehensive tests with sample videos in each format

**Task 2.2: Queue Dispatch**
- Implement Kafka producer with Protobuf serialization
- Configure partitioning by tenant_id + upload_id
- Add backpressure handling and circuit breaking
- Implement batch publishing for throughput optimization
- Add metrics instrumentation (frames processed, latency, errors)

### 3.2 L1 Scanner (veritas-l1-scanner)

**Task 2.3: Perceptual Hash Engine**
- Implement pHash, dHash, aHash algorithms in Rust
- Build Redis integration for hash lookup (batch queries)
- Implement Hamming distance calculation (SIMD-optimized)
- Design hash database ingestion pipeline (partner feeds)
- Build hash deduplication logic
- Target: < 1ms per hash lookup

**Task 2.4: Metadata Forensics**
- Implement EXIF/XMP parser (Rust exif crate)
- Build editing software signature database
- Implement timestamp consistency validation
- Add GOP structure analysis for re-encoding detection
- Implement bitrate consistency checker
- Build C2PA manifest validator

**Task 2.5: L1 Decision Logic**
- Implement decision matrix (BLOCK, escalate to L2, ALLOW)
- Add priority assignment for L2 queue
- Build L1 result publisher to Kafka
- Add metrics and structured logging

### 3.3 L2 Biometric Scanner (veritas-l2-biometric)

**Task 2.6: Micro-Flickering Detector**
- Implement face boundary tracking across frames
- Build Fourier transform analysis for boundary oscillation
- Define detection thresholds (configurable)
- Optimize for batch processing of frame sequences

**Task 2.7: rPPG Analyzer**
- Implement remote photoplethysmography signal extraction
- Build physiological plausibility validator (BPM range, signal coherence)
- Implement SNR calculation for signal quality assessment
- Add multi-region analysis (forehead, cheeks, chin)

**Task 2.8: Eye Movement Analyzer**
- Implement pupil tracking across frames
- Build saccade-fixation pattern analyzer
- Implement blink rate calculator
- Add corneal light reflection consistency check

**Task 2.9: L2 Integration**
- Combine all L2 signals into composite biometric score
- Implement decision matrix (ALLOW, escalate to L3)
- Build result publisher to Kafka
- Add performance profiling (target: < 150ms per face)

**Milestone**: L1 and L2 detection operational. System can process videos through two detection tiers and produce preliminary verdicts.

---

## 4. Phase 3: Intelligence Layer (Months 4-6)

### 4.1 ML Pipeline Setup

**Task 3.1: NVIDIA Triton Inference Server Setup**
- Deploy Triton on GPU nodes in Kubernetes
- Configure model repository on S3
- Set up model version management
- Configure dynamic batching parameters
- Implement health checks and readiness probes
- Performance benchmark (throughput, latency per model)

**Task 3.2: Model Training Infrastructure**
- Set up training pipeline (PyTorch + PyTorch Lightning)
- Configure training data storage and versioning (DVC or similar)
- Build training data loader for FaceForensics++, DFDC datasets
- Set up experiment tracking (MLflow or Weights & Biases)
- Implement automated training triggers

### 4.2 L3 Model Development

**Task 3.3: Vision Transformer (ViT-L/16)**
- Fine-tune pre-trained ViT on deepfake datasets
- Implement attention map extraction for XAI
- Export to ONNX for Triton serving
- Benchmark accuracy on holdout test set
- Target: > 95% accuracy on FaceForensics++ (c23)

**Task 3.4: EfficientNet-B7 GAN Detector**
- Train on StyleGAN/StyleGAN2/StyleGAN3/ProGAN outputs
- Implement spectral analysis branch
- Export to TensorRT for optimized inference
- Benchmark against GAN-specific test sets

**Task 3.5: Temporal Consistency Network**
- Implement 3D ConvNet architecture for temporal analysis
- Train on face-swap video sequences
- Implement frame sequence batching for Triton
- Benchmark on video-level deepfake detection

**Task 3.6: Diffusion Artifact Detector**
- Train on Stable Diffusion, DALL-E, Midjourney outputs
- Implement noise scheduling artifact analysis
- Design for continuous retraining as new models emerge
- Benchmark on latest diffusion-generated content

**Task 3.7: Audio-Visual Sync Analyzer**
- Implement SyncNet-based lip-sync analysis
- Build phoneme-viseme mapping validation
- Add voice deepfake detection via speaker embeddings
- Benchmark on dubbed/synthesized speech samples

### 4.3 Ensemble Aggregation

**Task 3.8: Ensemble Scorer**
- Implement weighted aggregation of model outputs
- Build disagreement detection logic
- Implement confidence calibration (Platt scaling)
- Design A/B testing framework for model versions
- Build canary deployment logic with automatic rollback

**Milestone**: Full three-tier detection operational. All ML models trained, validated, and serving via Triton.

---

## 5. Phase 4: Compliance & Security (Months 5-7)

### 5.1 Cryptographic Infrastructure

**Task 4.1: HSM Integration**
- Implement CloudHSM client in Rust
- Build key generation ceremony procedure
- Implement Ed25519 signing via HSM
- Build key rotation automation (90-day cycle)
- Implement public key publication (JWK endpoint)
- Build signature verification library (standalone, distributable)

**Task 4.2: Signing Service (veritas-signer)**
- Implement canonical JSON serialization
- Build SHA-512 hashing pipeline
- Integrate HSM client for signing operations
- Implement signature caching for deduplication
- Build OCSP responder for key revocation
- Target: < 10ms per signing operation

### 5.2 Compliance Engine

**Task 4.3: EU AI Act Logger**
- Implement per-scan documentation generation
- Build monthly report aggregation pipeline
- Implement model change tracking
- Build bias monitoring module (demographic accuracy variance)

**Task 4.4: C2PA Metadata Generator**
- Implement C2PA manifest structure (v2.0 specification)
- Build assertion generation (ai.analysis, ai.generated)
- Implement certificate chain embedding
- Integrate RFC 3161 timestamp authority
- Build manifest validation (round-trip test)

**Task 4.5: GDPR Zero-Retention Enforcer**
- Implement automated zero-retention verification scanner
- Build canary data injection and verification
- Implement memory scanning for biometric data leaks
- Build compliance alerting pipeline

**Task 4.6: DSA Transparency Module**
- Implement per-decision transparency record generation
- Build appeal data package generator
- Implement re-analysis workflow
- Build transparency report aggregation

### 5.3 XAI Engine

**Task 4.7: Reason Code Generator**
- Implement reason code taxonomy (all codes from System Design)
- Build natural language explanation generator (multi-language)
- Implement confidence score inclusion
- Build model version attribution

**Task 4.8: Visual Explanation Generator**
- Implement artifact heatmap generation (from attention maps)
- Build temporal confidence graph
- Implement side-by-side comparison view
- Build rPPG waveform visualization data

**Milestone**: All compliance modules operational. Cryptographic signing working. XAI engine generating explanations.

---

## 6. Phase 5: Dashboard & Integration (Months 6-8)

### 6.1 Dashboard Development

**Task 5.1: Dashboard Backend**
- Implement REST API for dashboard (TypeScript/Node.js or Rust/axum)
- Build WebSocket gateway for real-time updates
- Implement authentication (SSO/OIDC integration)
- Build role-based access control (RBAC)
- Implement query layer for ClickHouse and PostgreSQL

**Task 5.2: Real-Time Feed**
- Build live-updating feed of flagged content
- Implement WebSocket subscription management
- Add filtering by severity, tenant, detection type
- Build queue management UI

**Task 5.3: Decision Detail View**
- Build video player with artifact overlay
- Implement heatmap visualization component
- Build per-model confidence breakdown chart
- Implement rPPG signal visualization
- Build reason code display with explanations

**Task 5.4: Analytics Dashboard**
- Build detection volume charts (by tier, action, time)
- Implement false positive/negative tracking views
- Build model accuracy trend charts
- Implement geographic distribution map
- Build trending manipulation techniques view

**Task 5.5: Policy Management UI**
- Build visual threshold editor
- Implement policy simulation engine (historical data replay)
- Build audit log viewer for policy changes
- Implement tenant-specific policy configuration

**Task 5.6: Human Override Interface**
- Build one-click override with mandatory reason input
- Implement escalation workflow
- Build bulk review mode
- Implement reviewer performance tracking

### 6.2 Platform Integration

**Task 5.7: SDK Development**
- Build Rust client SDK (for high-performance platforms)
- Build Python client SDK
- Build Java/Kotlin client SDK (for Android-heavy platforms)
- Build Go client SDK
- All SDKs: connection management, retry logic, error handling, metrics

**Task 5.8: Integration Testing**
- Build integration test suite simulating platform traffic
- Implement contract testing (Pact)
- Build performance test harness (k6 or Locust)
- Create sample integration applications

**Milestone**: Dashboard fully functional. Client SDKs available. Integration tests passing.

---

## 7. Phase 6: Scaling & Performance (Months 7-9)

### 7.1 Performance Optimization

**Task 6.1: API Gateway Optimization**
- Profile and optimize gRPC handler performance
- Implement connection pooling tuning
- Add HTTP/2 flow control optimization
- Target: 50,000 RPS per gateway pod

**Task 6.2: ML Inference Optimization**
- Apply TensorRT optimization to all models
- Implement INT8 quantization for L2 models
- Optimize Triton batching parameters
- Implement model warm-up on pod startup
- Target: 2x throughput improvement over baseline

**Task 6.3: Data Layer Optimization**
- Optimize ClickHouse table schemas and materialized views
- Tune Redis cluster for hash lookup latency
- Optimize Kafka consumer configurations
- Implement read-through cache for frequently accessed data

### 7.2 Autoscaling

**Task 6.4: Kubernetes Autoscaling**
- Configure HPA for all services:
  - Gateway: CPU-based (target 60%)
  - L1 Scanner: Kafka lag-based (custom metrics)
  - L2 Biometric: Kafka lag + GPU utilization
  - L3 DeepNet: Kafka lag + GPU utilization + Triton queue depth
  - Scorer: CPU-based (target 60%)
- Configure VPA for right-sizing resource requests
- Configure Cluster Autoscaler for node pool scaling
- Implement pre-warming for GPU node pools
- Build custom metrics adapter for Kafka lag

**Task 6.5: Edge Computing Deployment**
- Deploy Tier 2 edge nodes in priority locations
- Configure edge hash database synchronization
- Implement edge-to-cloud connection pooling
- Deploy and test edge L1 pre-screening
- Measure and optimize edge-to-cloud latency

### 7.3 Load Testing

**Task 6.6: Load Testing Campaign**
- Design load test scenarios:
  - Sustained load: 10K RPS for 24 hours
  - Burst load: 50K RPS for 5 minutes
  - Ramp-up: 0 to 30K RPS over 30 minutes
  - Degraded mode: Test behavior with L3 offline
- Execute tests and identify bottlenecks
- Iterate on optimizations
- Document performance characteristics and limits

**Milestone**: System handles target throughput (10K+ RPS). Autoscaling operational. Edge nodes deployed.

---

## 8. Phase 7: Production Hardening (Months 9-11)

### 8.1 Resilience Engineering

**Task 7.1: Chaos Engineering**
- Implement chaos experiments (Chaos Mesh or Litmus):
  - Pod failure injection
  - Network partition simulation
  - Kafka broker failure
  - Redis node failure
  - GPU node failure
  - HSM connectivity loss
- Validate graceful degradation at each tier
- Document failure modes and recovery procedures

**Task 7.2: Disaster Recovery Testing**
- Execute full region failover test
- Validate RPO/RTO for all components
- Test backup restoration procedures
- Validate data integrity after failover
- Document runbooks for all DR scenarios

### 8.2 Security Hardening

**Task 7.3: Penetration Testing**
- Engage external security firm for penetration test
- Scope: API gateway, dashboard, gRPC interfaces, edge nodes
- Remediate all findings
- Re-test after remediation

**Task 7.4: Compliance Audit**
- Engage external auditor for EU AI Act compliance assessment
- GDPR Data Protection Impact Assessment (DPIA)
- Security certification preparation (SOC 2 Type II, ISO 27001)
- Address all audit findings

### 8.3 Observability

**Task 7.5: Monitoring Stack**
- Deploy full Prometheus + Grafana stack
- Implement OpenTelemetry tracing across all services
- Build alerting rules (PagerDuty/Opsgenie integration)
- Create runbooks for each alert
- Build SLO dashboards (error budget tracking)
- Implement log aggregation (OpenSearch)

**Task 7.6: Red-Team Sandbox**
- Deploy isolated sandbox environment
- Build red-team API endpoints
- Create automated attack report generator
- Test with internal adversarial samples
- Document sandbox usage procedures

**Milestone**: System hardened against failures and attacks. Monitoring comprehensive. Compliance audit passed.

---

## 9. Phase 8: Launch & Operations (Months 11-12)

### 9.1 Beta Launch

**Task 8.1: Beta Program**
- Onboard 2-3 beta platform partners
- Deploy to production infrastructure
- Monitor closely for 4 weeks
- Collect feedback on:
  - API ergonomics
  - Detection accuracy
  - Latency performance
  - Dashboard usability
  - Integration experience

**Task 8.2: Fine-Tuning**
- Adjust detection thresholds based on real-world data
- Optimize model weights with production data (where permitted)
- Tune autoscaling parameters based on actual traffic patterns
- Refine XAI explanations based on moderator feedback

### 9.2 General Availability

**Task 8.3: GA Launch Preparation**
- Complete all documentation:
  - API documentation (OpenAPI/Swagger)
  - Integration guides per platform
  - Compliance documentation package
  - Operational runbooks
- Set up customer support channels
- Prepare SLA definitions and contracts
- Complete marketing materials and technical blog posts

**Task 8.4: Operational Readiness**
- Establish on-call rotation (24/7)
- Complete runbook training for ops team
- Set up incident management process (PagerDuty + Jira/Linear)
- Establish change management procedure
- Set up regular model retraining cadence

**Milestone**: System in production serving real platform traffic. Operations team fully staffed and trained.

---

## 10. Team Structure

### 10.1 Recommended Team Composition

| Role | Count | Responsibility |
|------|-------|---------------|
| **Engineering Manager** | 1 | Overall technical leadership, roadmap management |
| **Rust Backend Engineers** | 4 | Gateway, ingestion, L1, scorer, signer services |
| **Python ML Engineers** | 3 | L2/L3 detection, model training, Triton integration |
| **ML Research Scientists** | 2 | Model architecture, training data curation, accuracy improvement |
| **DevOps/SRE Engineers** | 2 | Infrastructure, Kubernetes, CI/CD, monitoring |
| **Frontend Engineers** | 2 | Dashboard (React/TypeScript) |
| **Security Engineer** | 1 | HSM integration, crypto, pen testing, threat modeling |
| **Compliance Specialist** | 1 | EU AI Act, GDPR, DSA, documentation |
| **QA Engineer** | 1 | Integration testing, load testing, chaos engineering |
| **Product Manager** | 1 | Requirements, customer integration, roadmap prioritization |

**Total**: 18 people

### 10.2 Team Ramp-Up

| Month | Team Size | Focus |
|-------|-----------|-------|
| Month 1 | 8 | Core engineering (Rust + ML + DevOps) |
| Month 3 | 12 | Add frontend, security, QA |
| Month 5 | 16 | Add compliance, additional ML research |
| Month 8 | 18 | Full team for launch preparation |

---

## 11. Risk Register

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| GPU supply constraints | Medium | High | Reserve capacity early, multi-cloud GPU strategy |
| Model accuracy below target | Medium | High | Ensemble approach, continuous retraining, fallback to conservative thresholds |
| Kafka throughput bottleneck | Low | High | Extensive load testing, partitioning strategy, capacity planning |
| HSM latency spikes | Low | Medium | HSM clustering, async signing option, caching |
| Adversarial attacks bypassing detection | High | High | Red-team testing, rapid model update pipeline, multi-model ensemble |
| GDPR/AI Act regulatory changes | Medium | Medium | Modular compliance engine, legal monitoring |
| Key customer integration delays | Medium | Medium | Comprehensive SDK, integration support team |
| Rust hiring difficulty | Medium | Medium | Consider Go fallback for non-critical services |
| Cross-region latency exceeds budget | Low | Medium | Edge computing strategy, connection pooling |
| Single point of failure in signing | Low | Critical | HSM clustering, dual-key architecture, offline signing fallback |

---

## 12. Technology Prerequisites

### 12.1 Development Tools

| Tool | Purpose | Required By |
|------|---------|-------------|
| Rust 1.80+ | Backend services | Phase 1 |
| Python 3.12+ | ML services | Phase 1 |
| Protocol Buffers 3 | API contracts | Phase 1 |
| Docker + BuildKit | Container builds | Phase 1 |
| Terraform/OpenTofu | Infrastructure as Code | Phase 1 |
| Helm 3 | Kubernetes deployments | Phase 1 |
| buf | Protobuf linting and generation | Phase 1 |

### 12.2 External Services

| Service | Purpose | Required By |
|---------|---------|-------------|
| AWS/GCP Account | Cloud infrastructure | Phase 1 |
| GitHub/GitLab | Source control + CI/CD | Phase 1 |
| PagerDuty/Opsgenie | Incident management | Phase 7 |
| MLflow/W&B | Experiment tracking | Phase 3 |
| External Pen Test Firm | Security assessment | Phase 7 |
| External Auditor | Compliance certification | Phase 7 |

### 12.3 Datasets

| Dataset | Purpose | Required By |
|---------|---------|-------------|
| FaceForensics++ | ViT/EfficientNet training | Phase 3 |
| DFDC (Deepfake Detection Challenge) | Multi-model training | Phase 3 |
| CelebDF-v2 | Validation benchmark | Phase 3 |
| WildDeepfake | Real-world generalization testing | Phase 3 |
| Custom GAN outputs | GAN-specific training | Phase 3 |
| Custom diffusion outputs | Diffusion-specific training | Phase 3 |
