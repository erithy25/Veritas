# Veritas B2B - Data Flow Diagrams

**Version**: 1.0.0
**Format**: Mermaid
**Last Updated**: 2026-03-08

---

## 1. System Context Diagram

```mermaid
graph TB
    subgraph "External Platforms"
        YT[YouTube Upload Service]
        TT[TikTok Upload Service]
        META[Meta Upload Service]
    end

    subgraph "Veritas B2B"
        GW[API Gateway]
        CORE[Detection Engine]
        DASH[Moderator Dashboard]
    end

    subgraph "External Dependencies"
        HSM[Hardware Security Module]
        DFDB[Deepfake Database Partners]
        REG[EU AI Authority]
    end

    YT -->|gRPC/mTLS| GW
    TT -->|gRPC/mTLS| GW
    META -->|gRPC/mTLS| GW
    GW --> CORE
    CORE --> DASH
    CORE -->|Key Operations| HSM
    DFDB -->|Hash Feed| CORE
    CORE -->|Monthly Reports| REG

    style GW fill:#e74c3c,color:#fff
    style CORE fill:#3498db,color:#fff
    style DASH fill:#2ecc71,color:#fff
```

---

## 2. High-Level Data Flow

```mermaid
flowchart LR
    A[Platform Upload API] -->|Video Stream| B[Veritas Edge Proxy]
    B -->|Forwarded Stream| C[API Gateway]
    C -->|Authenticated Request| D[Ingestion Service]
    D -->|Extracted Frames| E{L1 Scanner}

    E -->|Clean| Z[ALLOW Response]
    E -->|Suspicious| F{L2 Biometric}
    E -->|Known Deepfake| Y[BLOCK Response]

    F -->|Clean| Z
    F -->|Anomalies Detected| G{L3 Deep Neural}

    G -->|All Results| H[Risk Scorer]
    H -->|Score + Context| I[Policy Engine]

    I -->|ALLOW| Z
    I -->|FLAG| J[Moderator Queue]
    I -->|BLOCK| K[Block + Notify]

    H -->|Result| L[Crypto Signer]
    L -->|Signed Verdict| M[Audit Log]

    style E fill:#27ae60,color:#fff
    style F fill:#f39c12,color:#fff
    style G fill:#e74c3c,color:#fff
    style L fill:#8e44ad,color:#fff
```

---

## 3. Detailed Ingestion Flow

```mermaid
sequenceDiagram
    participant P as Platform
    participant EP as Edge Proxy
    participant GW as API Gateway
    participant IS as Ingestion Service
    participant KF as Kafka
    participant L1 as L1 Scanner

    P->>EP: gRPC VideoUpload(stream)
    EP->>EP: Geographic routing
    EP->>GW: Forward stream
    GW->>GW: mTLS verify
    GW->>GW: JWT validate
    GW->>GW: Rate limit check
    GW->>IS: IngestVideo(metadata, stream)

    IS->>IS: Format detection
    IS->>IS: Integrity check
    IS->>IS: Frame extraction
    IS->>IS: Face detection (MTCNN)
    IS->>IS: Normalize face crops

    IS->>KF: Publish(veritas.ingest.raw)
    KF-->>L1: Consume(veritas.ingest.raw)

    Note over IS,KF: Frames partitioned by<br/>tenant_id + upload_id

    IS-->>GW: Ack(upload_id, frame_count)
    GW-->>P: UploadAccepted(upload_id)
```

---

## 4. Multi-Stage Detection Flow

```mermaid
sequenceDiagram
    participant KF as Kafka
    participant L1 as L1 Scanner
    participant RD as Redis Cache
    participant L2 as L2 Biometric
    participant L3 as L3 DeepNet
    participant TR as Triton Server
    participant SC as Risk Scorer
    participant PE as Policy Engine
    participant SG as Crypto Signer
    participant CK as ClickHouse

    KF->>L1: Consume(ingest.raw)

    rect rgb(200, 230, 200)
        Note over L1,RD: L1 - Metadata & Hash Check (~5ms)
        L1->>RD: pHash lookup
        RD-->>L1: Match result
        L1->>L1: Metadata forensics
        L1->>L1: Compression analysis
        L1->>KF: Publish(l1.results)
    end

    alt L1 = CLEAN
        L1->>SC: Score(l1_signals)
    else L1 = SUSPICIOUS
        L1->>KF: Publish(l2.queue)
        KF->>L2: Consume(l2.queue)

        rect rgb(255, 230, 200)
            Note over L2: L2 - Biometric Scan (~100ms)
            L2->>L2: Micro-flickering analysis
            L2->>L2: rPPG extraction
            L2->>L2: Eye movement tracking
            L2->>L2: Skin texture analysis
            L2->>KF: Publish(l2.results)
        end

        alt L2 = CLEAN
            L2->>SC: Score(l1_signals, l2_signals)
        else L2 = ANOMALIES
            L2->>KF: Publish(l3.queue)
            KF->>L3: Consume(l3.queue)

            rect rgb(255, 200, 200)
                Note over L3,TR: L3 - Deep Neural Analysis (~800ms)
                L3->>TR: ViT inference
                L3->>TR: EfficientNet inference
                L3->>TR: TCN inference
                L3->>TR: Diffusion detector
                L3->>TR: Lip-sync analyzer
                TR-->>L3: Ensemble results
                L3->>KF: Publish(l3.results)
            end

            L3->>SC: Score(l1 + l2 + l3 signals)
        end
    end

    SC->>SC: Compute risk score
    SC->>SC: Context enrichment
    SC->>PE: Evaluate(score, tenant_policy)
    PE-->>SC: Action(ALLOW|FLAG|BLOCK)

    SC->>SG: Sign(verdict)
    SG->>SG: HSM Ed25519 sign
    SG-->>SC: SignedVerdict

    SC->>CK: Store(signed_verdict)
    SC->>KF: Publish(verdicts)
```

---

## 5. Cryptographic Signing Flow

```mermaid
sequenceDiagram
    participant SC as Scorer
    participant SG as Signer Service
    participant HSM as Hardware Security Module
    participant PG as PostgreSQL
    participant CK as ClickHouse

    SC->>SG: SignRequest(verdict_data)

    SG->>SG: Canonical JSON serialization
    SG->>SG: SHA-512 hash
    SG->>HSM: Sign(hash, key_id)
    HSM->>HSM: Ed25519 sign with private key
    HSM-->>SG: Signature bytes

    SG->>SG: Assemble SignedVerdict
    Note over SG: SignedVerdict = {<br/>  verdict_data,<br/>  signature,<br/>  key_id,<br/>  algorithm,<br/>  timestamp,<br/>  cert_chain_url<br/>}

    SG->>PG: Store signature record
    SG->>CK: Store full verdict log
    SG-->>SC: SignedVerdict

    Note over PG: Signature records retained<br/>for 10 years (legal requirement)
```

---

## 6. Zero-Retention Biometric Data Flow

```mermaid
flowchart TD
    A[Video Frame Received] -->|RAM only| B[Face Crop Extraction]
    B -->|RAM only| C[Biometric Feature Extraction]
    C -->|RAM only| D[rPPG Analysis]
    C -->|RAM only| E[Micro-Flicker Analysis]
    C -->|RAM only| F[Eye Movement Analysis]
    C -->|RAM only| G[Skin Texture Analysis]

    D --> H[Score Generation]
    E --> H
    F --> H
    G --> H

    H -->|Scores only| I[Risk Scorer]
    H -->|secure_memzero| J[Biometric Data Destroyed]

    I -->|Non-biometric| K[(ClickHouse)]

    style J fill:#e74c3c,color:#fff
    style K fill:#3498db,color:#fff

    subgraph "Memory-Only Zone (tmpfs)"
        B
        C
        D
        E
        F
        G
        H
    end

    subgraph "Persistent Storage"
        K
    end
```

---

## 7. Compliance Event Flow

```mermaid
flowchart LR
    subgraph "Detection Pipeline"
        V[Verdict Generated]
    end

    subgraph "Compliance Engine"
        CE[Compliance Processor]
        C2[C2PA Metadata Generator]
        XAI[XAI Reason Code Engine]
        AL[AI Act Logger]
    end

    subgraph "Outputs"
        PM[Platform Metadata API]
        AR[Audit Repository]
        RR[Regulatory Reporter]
        MB[Monthly EU AI Report]
    end

    V --> CE
    CE --> C2
    CE --> XAI
    CE --> AL

    C2 -->|C2PA Manifest| PM
    XAI -->|Reason Codes| PM
    AL -->|Transparency Log| AR

    AR -->|Aggregated Data| RR
    RR -->|Monthly| MB

    style CE fill:#8e44ad,color:#fff
    style C2 fill:#2980b9,color:#fff
    style XAI fill:#27ae60,color:#fff
    style AL fill:#d35400,color:#fff
```

---

## 8. Moderator Dashboard Data Flow

```mermaid
sequenceDiagram
    participant KF as Kafka
    participant WS as WebSocket Gateway
    participant DB as Dashboard Backend
    participant CK as ClickHouse
    participant PG as PostgreSQL
    participant UI as Moderator Browser

    KF->>WS: Consume(verdicts) [FLAG/BLOCK only]
    WS->>UI: Push(new_flagged_content)

    UI->>DB: GetVerdictDetail(verdict_id)
    DB->>CK: Query detection signals
    DB->>PG: Query signature + policy
    DB-->>UI: VerdictDetail + XAI Explanations

    UI->>UI: Render heatmap overlay
    UI->>UI: Render rPPG waveform
    UI->>UI: Render model confidence chart

    Note over UI: Moderator reviews content

    alt Override Decision
        UI->>DB: OverrideVerdict(verdict_id, new_action, reason)
        DB->>PG: Store override with audit trail
        DB->>KF: Publish(verdict_override)
        DB-->>UI: OverrideConfirmed
    end
```

---

## 9. Autoscaling Decision Flow

```mermaid
flowchart TD
    A[Prometheus Metrics] --> B{Queue Depth Check}

    B -->|Kafka lag > 10k msgs| C[Scale Up L1 Pods]
    B -->|Kafka lag > 50k msgs| D[Scale Up L1 + L2 Pods]
    B -->|L3 queue > 5k msgs| E[Scale Up L3 GPU Pods]
    B -->|All queues < 1k msgs| F{CPU/GPU Utilization}

    F -->|GPU > 80%| G[Scale Up GPU Pods]
    F -->|CPU > 70%| H[Scale Up CPU Pods]
    F -->|All < 40%| I[Scale Down Pods]

    C --> J[Kubernetes HPA]
    D --> J
    E --> J
    G --> J
    H --> J
    I --> J

    J --> K[Pod Scaling Event]
    K --> L[Update Kafka Consumer Group]
    K --> M[Update Load Balancer]

    style B fill:#f39c12,color:#fff
    style J fill:#3498db,color:#fff
```

---

## 10. Red Team Sandbox Flow

```mermaid
flowchart LR
    subgraph "Isolated Network"
        RT[Red Team Client] -->|Adversarial Samples| SB[Sandbox Gateway]
        SB --> SBL1[Sandbox L1]
        SB --> SBL2[Sandbox L2]
        SB --> SBL3[Sandbox L3]
        SBL1 --> SBS[Sandbox Scorer]
        SBL2 --> SBS
        SBL3 --> SBS
    end

    subgraph "Production"
        PROD[Production Pipeline]
    end

    SBS --> RPT[Attack Report Generator]
    RPT --> VULN[Vulnerability Assessment]
    VULN -->|Manual Review| PROD

    style RT fill:#e74c3c,color:#fff
    style SB fill:#f39c12,color:#fff
    style PROD fill:#27ae60,color:#fff

    Note over RT,SBS: Complete network isolation<br/>No production data access<br/>Separate model copies
```

---

## 11. Global Edge Network Topology

```mermaid
graph TB
    subgraph "North America"
        NA1[Edge PoP: US-East<br/>Virginia]
        NA2[Edge PoP: US-West<br/>Oregon]
    end

    subgraph "Europe"
        EU1[Edge PoP: EU-West<br/>Frankfurt]
        EU2[Edge PoP: EU-North<br/>Stockholm]
    end

    subgraph "Asia Pacific"
        AP1[Edge PoP: AP-East<br/>Tokyo]
        AP2[Edge PoP: AP-South<br/>Singapore]
    end

    subgraph "Analysis Regions"
        AR1[Analysis Cluster<br/>US-East]
        AR2[Analysis Cluster<br/>EU-West]
        AR3[Analysis Cluster<br/>AP-East]
    end

    NA1 -->|Nearest cluster| AR1
    NA2 -->|Nearest cluster| AR1
    EU1 -->|Nearest cluster| AR2
    EU2 -->|Nearest cluster| AR2
    AP1 -->|Nearest cluster| AR3
    AP2 -->|Nearest cluster| AR3

    AR1 <-->|Cross-region sync| AR2
    AR2 <-->|Cross-region sync| AR3
    AR1 <-->|Cross-region sync| AR3

    style NA1 fill:#e74c3c,color:#fff
    style NA2 fill:#e74c3c,color:#fff
    style EU1 fill:#3498db,color:#fff
    style EU2 fill:#3498db,color:#fff
    style AP1 fill:#27ae60,color:#fff
    style AP2 fill:#27ae60,color:#fff
```

---

## 12. End-to-End Request Lifecycle

```mermaid
stateDiagram-v2
    [*] --> EdgeReceived: Video uploaded
    EdgeReceived --> Authenticated: mTLS + JWT verified
    Authenticated --> Ingesting: Frames extracted
    Ingesting --> L1Scanning: Hash + metadata check

    L1Scanning --> Allowed: Clean (hash match, valid C2PA)
    L1Scanning --> L2Scanning: Suspicious signals
    L1Scanning --> Blocked: Known deepfake hash

    L2Scanning --> Allowed: Biometrics consistent
    L2Scanning --> L3Scanning: Anomalies detected

    L3Scanning --> Scoring: Neural analysis complete

    Scoring --> Allowed: Score < 0.30
    Scoring --> Flagged: Score 0.30 - 0.85
    Scoring --> Blocked: Score > 0.85

    Allowed --> Signed: Verdict signed
    Flagged --> ModeratorReview: Queued for human review
    Blocked --> Signed: Verdict signed

    ModeratorReview --> Allowed: Moderator override
    ModeratorReview --> Blocked: Moderator confirms

    Signed --> AuditLogged: Stored in ClickHouse
    AuditLogged --> ResponseSent: gRPC response to platform
    ResponseSent --> [*]

    Signed --> ComplianceProcessed: EU AI Act logging
    ComplianceProcessed --> C2PAGenerated: Content credentials
```

---

## 13. Kafka Topic Dependency Graph

```mermaid
flowchart TD
    subgraph "Ingestion"
        T1[veritas.ingest.raw<br/>256 partitions]
    end

    subgraph "L1 Processing"
        T2[veritas.l1.results<br/>128 partitions]
    end

    subgraph "L2 Processing"
        T3[veritas.l2.queue<br/>128 partitions]
        T4[veritas.l2.results<br/>128 partitions]
    end

    subgraph "L3 Processing"
        T5[veritas.l3.queue<br/>64 partitions]
        T6[veritas.l3.results<br/>64 partitions]
    end

    subgraph "Verdicts & Compliance"
        T7[veritas.verdicts<br/>256 partitions]
        T8[veritas.compliance.events<br/>32 partitions]
        T9[veritas.alerts<br/>16 partitions]
    end

    T1 -->|L1 consumers| T2
    T2 -->|Suspicious| T3
    T3 -->|L2 consumers| T4
    T4 -->|Anomalies| T5
    T5 -->|L3 consumers| T6

    T2 --> T7
    T4 --> T7
    T6 --> T7

    T7 --> T8
    T7 --> T9
```
