# Veritas B2B - Cloud Infrastructure Components

**Version**: 1.0.0
**Last Updated**: 2026-03-08

---

## Table of Contents

1. [Multi-Cloud Strategy](#1-multi-cloud-strategy)
2. [AWS Component Mapping](#2-aws-component-mapping)
3. [GCP Component Mapping](#3-gcp-component-mapping)
4. [Azure Component Mapping](#4-azure-component-mapping)
5. [Global Deployment Regions](#5-global-deployment-regions)
6. [Network Architecture](#6-network-architecture)
7. [Storage Architecture](#7-storage-architecture)
8. [GPU Compute Strategy](#8-gpu-compute-strategy)
9. [Cost Estimation Framework](#9-cost-estimation-framework)
10. [Disaster Recovery](#10-disaster-recovery)

---

## 1. Multi-Cloud Strategy

### 1.1 Cloud-Agnostic Design Principle

Veritas is designed for multi-cloud deployment to avoid vendor lock-in and to meet data sovereignty requirements. The core application runs on Kubernetes, with cloud-specific services abstracted behind provider interfaces.

### 1.2 Primary Cloud Selection Criteria

| Criterion | AWS | GCP | Azure |
|-----------|-----|-----|-------|
| GPU Availability (A100/H100) | Excellent | Excellent | Good |
| Kubernetes Maturity | EKS (Mature) | GKE (Best-in-class) | AKS (Mature) |
| HSM Service | CloudHSM (FIPS 140-2 L3) | Cloud HSM (FIPS 140-2 L3) | Dedicated HSM (FIPS 140-2 L3) |
| Edge Network | CloudFront (400+ PoPs) | Cloud CDN (180+ PoPs) | Front Door (180+ PoPs) |
| EU Data Residency | Full support | Full support | Full support |
| Kafka Managed | MSK | Confluent on GCP | Event Hubs (Kafka API) |
| Cost (GPU workloads) | Competitive | Best (sustained use) | Competitive |

**Recommendation**: Primary deployment on **AWS** (broadest edge network, most HSM locations), with **GCP** as secondary for EU data residency and ML workloads.

---

## 2. AWS Component Mapping

### 2.1 Compute

| Veritas Component | AWS Service | Instance Type | Notes |
|-------------------|-------------|---------------|-------|
| API Gateway | EKS (Fargate or EC2) | c7g.2xlarge (Graviton3) | ARM for cost efficiency on pure networking |
| Ingestion Service | EKS (EC2) | c7g.4xlarge | CPU-bound frame extraction |
| L1 Scanner | EKS (EC2) | c7g.2xlarge | CPU + Redis access |
| L2 Biometric | EKS (EC2) | g5.2xlarge (T4 GPU) | Optional GPU acceleration |
| L3 DeepNet | EKS (EC2) | p5.48xlarge (H100) or p4d.24xlarge (A100) | Dedicated GPU nodes |
| Triton Server | EKS (EC2) | p4d.24xlarge | 8x A100 for model serving |
| Scorer | EKS (Fargate) | 2 vCPU, 4 GB | Lightweight compute |
| Signer | EKS (EC2) | c7g.large | Needs VPC connectivity to CloudHSM |
| Dashboard Backend | EKS (Fargate) | 2 vCPU, 4 GB | Stateless API |
| Dashboard Frontend | S3 + CloudFront | - | Static SPA hosting |
| Compliance Engine | EKS (Fargate) | 2 vCPU, 4 GB | Event-driven processing |

### 2.2 Data & Storage

| Veritas Component | AWS Service | Configuration |
|-------------------|-------------|---------------|
| Message Queue | Amazon MSK (Kafka) | kafka.m5.4xlarge, 6 brokers, 1TB SSD per broker |
| Hash Cache | Amazon ElastiCache (Redis) | cache.r7g.2xlarge, 6-node cluster, cluster mode |
| Analytics DB | Self-managed ClickHouse on EC2 | i4i.4xlarge (NVMe), 3-node cluster |
| Signature DB | Amazon RDS PostgreSQL + TimescaleDB | db.r7g.2xlarge, Multi-AZ, 1TB gp3 |
| Model Storage | Amazon S3 | Standard tier, versioning enabled |
| Audit Logs | Amazon S3 + Glacier | S3 for 1 year, Glacier Deep Archive for 10 years |
| Config Store | AWS Systems Manager Parameter Store | Encrypted parameters |
| Secrets | AWS Secrets Manager | Automatic rotation |

### 2.3 Security

| Veritas Component | AWS Service | Configuration |
|-------------------|-------------|---------------|
| HSM | AWS CloudHSM | 2+ HSM instances in cluster (HA) |
| Certificate Management | AWS Certificate Manager (ACM) | Public + private CAs |
| Key Management (non-signing) | AWS KMS | Customer-managed CMKs |
| WAF | AWS WAF v2 | Custom rules for API protection |
| DDoS Protection | AWS Shield Advanced | Always-on network flow monitoring |
| VPC | Amazon VPC | Private subnets, no public IPs on workloads |
| Network Firewall | AWS Network Firewall | Stateful inspection for egress |

### 2.4 Networking

| Veritas Component | AWS Service | Configuration |
|-------------------|-------------|---------------|
| Edge Proxy | Amazon CloudFront | Custom origin, Lambda@Edge for routing |
| DNS | Amazon Route 53 | Latency-based routing, health checks |
| Load Balancer | AWS ALB / NLB | NLB for gRPC (TCP passthrough), ALB for REST |
| Service Mesh | AWS App Mesh or Istio on EKS | mTLS between services |
| VPN (Red Team) | AWS Site-to-Site VPN | Dedicated VPN for sandbox access |
| PrivateLink | AWS PrivateLink | Customer connectivity without public internet |

### 2.5 Monitoring & Observability

| Veritas Component | AWS Service | Configuration |
|-------------------|-------------|---------------|
| Metrics | Amazon Managed Prometheus | Self-managed Prometheus alternative |
| Dashboards | Amazon Managed Grafana | Connected to Prometheus + CloudWatch |
| Logging | Amazon OpenSearch Service | Centralized log aggregation |
| Tracing | AWS X-Ray + OpenTelemetry | Distributed tracing |
| Alerting | Amazon SNS + PagerDuty integration | Multi-channel alerting |
| Cost Monitoring | AWS Cost Explorer + Budgets | Per-tenant cost allocation |

---

## 3. GCP Component Mapping

### 3.1 Compute

| Veritas Component | GCP Service | Machine Type |
|-------------------|-------------|--------------|
| API Gateway | GKE Autopilot | c3-standard-8 |
| Ingestion Service | GKE Standard | c3-standard-16 |
| L1 Scanner | GKE Autopilot | c3-standard-8 |
| L2 Biometric | GKE Standard | g2-standard-8 (L4 GPU) |
| L3 DeepNet | GKE Standard | a3-highgpu-8g (H100) or a2-highgpu-4g (A100) |
| Triton Server | GKE Standard | a2-highgpu-8g |
| Dashboard Frontend | Cloud Storage + Cloud CDN | - |
| Serverless Functions | Cloud Run | Compliance event processing |

### 3.2 Data & Storage

| Veritas Component | GCP Service | Configuration |
|-------------------|-------------|---------------|
| Message Queue | Confluent Cloud on GCP or Pub/Sub | Dedicated Kafka cluster |
| Hash Cache | Memorystore for Redis | M2 tier, 6 nodes, cluster mode |
| Analytics DB | Self-managed ClickHouse on GCE | n2-highmem-16 (local SSD) |
| Signature DB | Cloud SQL PostgreSQL | db-custom-8-32768, HA regional |
| Model Storage | Cloud Storage | Standard, versioned |
| Audit Logs | Cloud Storage + Coldline | Lifecycle policies |

### 3.3 Security

| Veritas Component | GCP Service |
|-------------------|-------------|
| HSM | Cloud HSM (FIPS 140-2 Level 3) |
| Certificate Management | Certificate Authority Service |
| Key Management | Cloud KMS |
| DDoS | Cloud Armor |
| VPC | VPC with Private Google Access |

---

## 4. Azure Component Mapping

### 4.1 Compute

| Veritas Component | Azure Service | VM Size |
|-------------------|---------------|---------|
| API Gateway | AKS | Standard_D8as_v5 |
| L3 DeepNet | AKS | Standard_NC80adis_H100_v5 |
| Triton Server | AKS | Standard_ND96amsr_A100_v4 |
| Dashboard Frontend | Azure Static Web Apps | - |

### 4.2 Data & Storage

| Veritas Component | Azure Service |
|-------------------|---------------|
| Message Queue | Azure Event Hubs (Kafka API) or Confluent Cloud |
| Hash Cache | Azure Cache for Redis |
| Signature DB | Azure Database for PostgreSQL Flexible Server |
| Model Storage | Azure Blob Storage |

### 4.3 Security

| Veritas Component | Azure Service |
|-------------------|---------------|
| HSM | Azure Dedicated HSM (FIPS 140-2 Level 3) |
| Key Management | Azure Key Vault (Managed HSM) |
| DDoS | Azure DDoS Protection |
| WAF | Azure Application Gateway WAF v2 |

---

## 5. Global Deployment Regions

### 5.1 Region Selection

| Region | Primary Cloud | Purpose | Data Residency |
|--------|--------------|---------|----------------|
| US-East (Virginia) | AWS us-east-1 | Americas primary | US |
| US-West (Oregon) | AWS us-west-2 | Americas secondary | US |
| EU-West (Frankfurt) | AWS eu-central-1 | EU primary, GDPR anchor | EU |
| EU-North (Stockholm) | GCP europe-north1 | EU secondary, Nordic data residency | EU |
| EU-West (Ireland) | AWS eu-west-1 | EU tertiary | EU |
| AP-Northeast (Tokyo) | AWS ap-northeast-1 | APAC primary | Japan |
| AP-Southeast (Singapore) | GCP asia-southeast1 | APAC secondary | Singapore |
| ME-South (Bahrain) | AWS me-south-1 | Middle East | Bahrain |

### 5.2 Data Residency Enforcement

```
Tenant(jurisdiction=EU) → Request arrives at any edge PoP →
Routed to EU analysis cluster (Frankfurt/Stockholm) →
All processing within EU → Result stored in EU →
Response returned via same edge PoP
```

- **EU tenants**: All biometric processing, storage, and signing occurs exclusively in EU regions
- **US tenants**: Processing in US regions only
- **Global tenants**: Processing in nearest region, cross-region sync for hash databases only

### 5.3 Edge PoP Locations (CDN/Proxy)

Using AWS CloudFront (400+ PoPs) or Cloudflare (300+ PoPs):

| Tier | Locations | Purpose |
|------|-----------|---------|
| Tier 1 | 50+ major metro areas globally | Full proxy + initial validation |
| Tier 2 | 150+ secondary locations | TCP termination + forwarding |
| Tier 3 | 200+ additional PoPs | DNS-level routing only |

---

## 6. Network Architecture

### 6.1 VPC Design (per region)

```
VPC: 10.{region_id}.0.0/16

Subnets:
├── Public Subnet (10.x.0.0/20)
│   ├── NAT Gateways
│   └── Load Balancers (NLB/ALB)
│
├── Private Subnet - Application (10.x.16.0/20)
│   ├── EKS Worker Nodes (non-GPU)
│   ├── API Gateway pods
│   ├── Ingestion pods
│   ├── L1/Scorer/Signer pods
│   └── Dashboard backend pods
│
├── Private Subnet - GPU (10.x.32.0/20)
│   ├── EKS GPU Worker Nodes
│   ├── L2 Biometric pods
│   ├── L3 DeepNet pods
│   └── Triton Server pods
│
├── Private Subnet - Data (10.x.48.0/20)
│   ├── MSK (Kafka) brokers
│   ├── ElastiCache (Redis) cluster
│   ├── ClickHouse nodes
│   └── RDS PostgreSQL
│
├── Private Subnet - Security (10.x.64.0/24)
│   ├── CloudHSM instances
│   └── Signer service (exclusive access)
│
└── Isolated Subnet - Sandbox (10.x.128.0/20)
    ├── Red Team sandbox environment
    └── No connectivity to production subnets
```

### 6.2 Network Security Groups

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| CloudFront | NLB | 443 | TCP | Inbound API traffic |
| Application subnet | Data subnet | 9092 | TCP | Kafka |
| Application subnet | Data subnet | 6379 | TCP | Redis |
| Application subnet | Data subnet | 8123 | TCP | ClickHouse |
| Application subnet | Data subnet | 5432 | TCP | PostgreSQL |
| Application subnet | GPU subnet | 8001 | TCP | Triton gRPC |
| Security subnet | HSM ENI | 2223-2225 | TCP | CloudHSM |
| All subnets | 0.0.0.0/0 | - | - | DENIED (egress via NAT only) |

### 6.3 Cross-Region Connectivity

- **AWS Transit Gateway**: Hub-and-spoke connectivity between regions
- **Encrypted peering**: All cross-region traffic encrypted with AES-256-GCM
- **Bandwidth**: Minimum 10 Gbps between primary regions
- **Latency budget**: Cross-region sync must not impact request processing (async only)

---

## 7. Storage Architecture

### 7.1 Storage Tiers

| Data Type | Storage | Retention | Encryption | Backup |
|-----------|---------|-----------|------------|--------|
| Video frames (in-flight) | tmpfs (RAM) | Seconds | In-memory only | None (ephemeral) |
| Biometric vectors | tmpfs (RAM) | Seconds | In-memory only | None (ephemeral) |
| Hash database | Redis | Indefinite | AES-256 at rest | Daily snapshot |
| Detection logs | ClickHouse | 2 years active | AES-256 at rest | Daily to S3 |
| Signed verdicts | PostgreSQL | 10 years | AES-256 at rest | Continuous replication |
| Audit archive | S3 → Glacier | 10 years | SSE-KMS | Cross-region replication |
| ML models | S3 | All versions retained | SSE-KMS | Cross-region replication |
| Kafka messages | MSK (EBS) | Topic-specific | AES-256 | Built-in replication |
| Moderator actions | PostgreSQL | 10 years | AES-256 | Continuous replication |
| Tenant configs | PostgreSQL | Active | AES-256 | Continuous replication |

### 7.2 Backup Strategy

| Component | RPO | RTO | Method |
|-----------|-----|-----|--------|
| PostgreSQL | 0 (sync replication) | < 5 min (auto-failover) | Multi-AZ + cross-region read replica |
| ClickHouse | 1 hour | < 30 min | Hourly snapshots to S3 + replication |
| Redis | 1 hour | < 5 min (auto-failover) | AOF + hourly RDB snapshots |
| Kafka | 0 (ISR replication) | < 5 min | 3x replication factor |
| S3/GCS | 0 (synchronous) | 0 | Cross-region replication |

---

## 8. GPU Compute Strategy

### 8.1 GPU Instance Selection

| Workload | GPU Type | VRAM | Instance | Use Case |
|----------|----------|------|----------|----------|
| L2 Biometric (optional) | NVIDIA T4 | 16 GB | g5.xlarge (AWS) | Lightweight inference |
| L3 Inference (primary) | NVIDIA A100 | 80 GB | p4d.24xlarge (AWS) | Multi-model serving |
| L3 Inference (high-perf) | NVIDIA H100 | 80 GB | p5.48xlarge (AWS) | Peak throughput |
| Model Training | NVIDIA A100 | 80 GB | p4d.24xlarge | Periodic retraining |

### 8.2 GPU Sharing Strategy (Triton)

NVIDIA Triton Inference Server enables multi-model sharing on a single GPU:

- **Model Parallelism**: Large models split across multiple GPUs
- **Concurrent Model Execution**: Multiple smaller models share a single GPU
- **Dynamic Batching**: Requests batched automatically for throughput optimization
- **Model Prioritization**: L3 models prioritized over batch retraining jobs

**Triton Configuration per GPU Node (8x A100)**:

```
GPU 0-1: ViT-L/16 (General Purpose) - 2 model instances
GPU 2-3: EfficientNet-B7 (GAN Detector) - 4 model instances
GPU 4:   Temporal Consistency Network - 1 model instance
GPU 5:   Diffusion Artifact Detector - 2 model instances
GPU 6:   Audio-Visual Sync Analyzer - 2 model instances
GPU 7:   Reserved for canary deployments / A-B testing
```

### 8.3 GPU Autoscaling

- **Metric**: Triton queue depth + GPU utilization
- **Scale-up trigger**: Queue depth > 100 OR GPU utilization > 80% for 2 minutes
- **Scale-down trigger**: Queue depth < 10 AND GPU utilization < 30% for 10 minutes
- **Minimum nodes**: 2 (HA) per region
- **Maximum nodes**: 32 per region (configurable per tenant SLA)
- **Scale-up time**: ~3 minutes (pre-warmed node pool with models pre-loaded on AMI)

### 8.4 Cost Optimization

1. **Spot/Preemptible Instances**: Use for L2 workloads (can retry on preemption)
2. **Reserved Instances**: 1-year reserved for minimum GPU fleet
3. **Savings Plans**: Compute Savings Plan for baseline CPU workloads
4. **Inference Optimization**: ONNX Runtime + TensorRT for 2-4x inference speedup
5. **Quantization**: INT8 quantization for L2 models (minimal accuracy loss, 2x throughput)
6. **Model Distillation**: Smaller student models for common deepfake patterns

---

## 9. Cost Estimation Framework

### 9.1 Monthly Cost Breakdown (Single Region, 10K RPS)

| Category | Component | Monthly Cost (USD) |
|----------|-----------|-------------------|
| **Compute (CPU)** | EKS workers (20x c7g.2xlarge) | ~$8,000 |
| **Compute (GPU)** | GPU nodes (4x p4d.24xlarge reserved) | ~$52,000 |
| **Compute (GPU)** | GPU nodes (burst, spot) | ~$5,000 - $15,000 |
| **Data** | MSK (6 brokers, m5.4xlarge) | ~$12,000 |
| **Data** | ElastiCache Redis (6x r7g.2xlarge) | ~$9,000 |
| **Data** | ClickHouse (3x i4i.4xlarge) | ~$10,000 |
| **Data** | RDS PostgreSQL (Multi-AZ, r7g.2xlarge) | ~$4,000 |
| **Security** | CloudHSM (2 instances) | ~$3,000 |
| **Networking** | CloudFront + data transfer | ~$8,000 |
| **Monitoring** | Prometheus + Grafana + logging | ~$3,000 |
| **Storage** | S3 (models, archives) | ~$2,000 |
| **Other** | DNS, secrets, certificates | ~$500 |
| | **Total (Single Region)** | **~$116,500 - $126,500** |
| | **Total (3 Regions, HA)** | **~$350,000 - $380,000** |

### 9.2 Per-Request Cost

At 10,000 RPS (26.8M requests/month):
- **Average cost per request**: $0.013 - $0.014
- **L1-only cost per request**: ~$0.001
- **L1+L2 cost per request**: ~$0.005
- **L1+L2+L3 cost per request**: ~$0.05

### 9.3 Cost Scaling

| Throughput | Monthly Cost (3 regions) | Per-Request Cost |
|------------|------------------------|-----------------|
| 1,000 RPS | ~$180,000 | $0.069 |
| 10,000 RPS | ~$365,000 | $0.014 |
| 50,000 RPS | ~$1,200,000 | $0.009 |
| 100,000 RPS | ~$2,100,000 | $0.008 |

---

## 10. Disaster Recovery

### 10.1 Recovery Objectives

| Component | RPO | RTO | Strategy |
|-----------|-----|-----|----------|
| API Gateway | 0 | < 1 min | Active-active multi-region |
| Detection Pipeline | < 1 min | < 5 min | Active-passive with warm standby |
| Signature Database | 0 | < 5 min | Synchronous replication |
| Analytics Database | < 1 hour | < 30 min | Async replication + snapshots |
| ML Models | 0 | < 10 min | S3 cross-region replication |
| HSM Keys | 0 | < 15 min | HSM cluster HA + DR key copies |

### 10.2 Failover Architecture

```
Normal Operation:
  Primary Region (eu-central-1) ← All EU traffic
  Secondary Region (eu-west-1) ← Warm standby

Failover Trigger:
  Health checks fail for 30 seconds on primary

Automatic Failover:
  Route 53 health check → Update DNS → Traffic flows to secondary
  Secondary region promotes read replicas to primary
  Kafka MirrorMaker ensures message continuity

Recovery:
  Primary region restored → Catch up from replication log
  Traffic gradually shifted back (10% → 50% → 100%)
```

### 10.3 Multi-Region Active-Active (Premium Tier)

For tenants requiring zero-downtime guarantees:
- Both regions process requests simultaneously
- Kafka MirrorMaker 2 for bidirectional topic replication
- CRDTs for eventual consistency of non-critical state
- Split-brain prevention via distributed lock (etcd/ZooKeeper)
- Hash database synchronized across all regions in real-time
