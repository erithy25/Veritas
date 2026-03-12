# Veritas B2B - Security Architecture

**Version**: 1.0.0
**Last Updated**: 2026-03-08
**Classification**: Confidential

---

## Table of Contents

1. [Security Principles](#1-security-principles)
2. [Threat Model](#2-threat-model)
3. [Authentication & Identity](#3-authentication--identity)
4. [Encryption Architecture](#4-encryption-architecture)
5. [Cryptographic Signing System](#5-cryptographic-signing-system)
6. [Network Security](#6-network-security)
7. [Application Security](#7-application-security)
8. [Supply Chain Security](#8-supply-chain-security)
9. [Operational Security](#9-operational-security)
10. [Incident Response](#10-incident-response)
11. [Compliance Certifications](#11-compliance-certifications)

---

## 1. Security Principles

### 1.1 Core Security Tenets

1. **Zero Trust**: No implicit trust between services. Every request authenticated and authorized.
2. **Defense in Depth**: Multiple independent security layers. Compromise of one layer doesn't compromise the system.
3. **Least Privilege**: Every service, user, and process has only the minimum permissions required.
4. **Privacy by Architecture**: Biometric data physically cannot be persisted. Not policy, architecture.
5. **Cryptographic Non-Repudiation**: Every detection result is cryptographically signed and independently verifiable.
6. **Assume Breach**: Security controls designed assuming an attacker has already gained initial access.
7. **Audit Everything**: All security-relevant actions logged immutably with tamper detection.

### 1.2 Security Ownership

| Domain | Owner | Responsibilities |
|--------|-------|-----------------|
| Application Security | Security Engineer | Code review, SAST/DAST, dependency scanning |
| Infrastructure Security | SRE Team | Network policies, node hardening, access control |
| Cryptographic Operations | Security Engineer | HSM management, key ceremonies, signing integrity |
| Compliance Security | Compliance Specialist | Regulatory controls, audit preparation, reporting |
| Detection Security | ML Team | Adversarial robustness, model integrity, red-teaming |

---

## 2. Threat Model

### 2.1 STRIDE Analysis

| Threat | Category | Description | Mitigation |
|--------|----------|-------------|------------|
| T1 | Spoofing | Attacker impersonates a platform tenant | mTLS + API key authentication, certificate pinning |
| T2 | Tampering | Attacker modifies video data in transit | TLS 1.3 for all connections, integrity checks |
| T3 | Tampering | Attacker modifies detection results | Ed25519 cryptographic signing via HSM |
| T4 | Repudiation | Tenant denies receiving a verdict | Signed verdicts with timestamp, webhook delivery receipts |
| T5 | Information Disclosure | Biometric data leaked from memory | Zero-retention architecture, memory isolation, swap disabled |
| T6 | Information Disclosure | Detection model weights stolen | Models encrypted at rest, no model download API |
| T7 | Denial of Service | Attacker floods API with requests | Rate limiting, WAF, DDoS protection, load shedding |
| T8 | Elevation of Privilege | Attacker gains access to HSM | HSM access limited to signer service, network isolation |
| T9 | Adversarial Attack | Deepfakes crafted to bypass detection | Multi-model ensemble, continuous retraining, red-teaming |
| T10 | Supply Chain | Compromised dependency injected | Dependency scanning, SBOM, reproducible builds |
| T11 | Insider Threat | Employee accesses tenant data | RBAC, audit logging, privileged access management |
| T12 | Data Exfiltration | Biometric data exfiltrated via logging | Log sanitization, no biometric data in any log output |

### 2.2 Attack Surface

```
External Attack Surface:
├── API Gateway (port 443)
│   ├── gRPC endpoint
│   ├── REST endpoint
│   └── WebSocket (dashboard)
├── Edge Proxy Nodes
├── Webhook delivery (outbound)
└── Public key endpoint (/.well-known/)

Internal Attack Surface:
├── Inter-service gRPC (Istio mTLS)
├── Kafka broker communication
├── Redis cluster communication
├── Database connections
├── HSM communication channel
├── Container runtime
├── Kubernetes API server
└── CI/CD pipeline
```

### 2.3 High-Value Assets

| Asset | Sensitivity | Protection |
|-------|-----------|-----------|
| HSM Private Keys | Critical | FIPS 140-2 L3 HSM, M-of-N access |
| ML Model Weights | High | Encrypted storage, no export API |
| Tenant API Keys | High | Hashed storage, rotation capability |
| Detection Results | High | Cryptographic signing, immutable storage |
| Biometric Data (in-flight) | Critical | RAM-only, zero-retention, memory isolation |
| Tenant Configuration | Medium | Encrypted database, RBAC |
| System Logs | Medium | Centralized, tamper-evident |

---

## 3. Authentication & Identity

### 3.1 External Authentication

**mTLS (Primary)**:
- Each tenant receives a client certificate from Veritas CA
- Certificate includes: tenant_id (CN), permissions (SAN extensions)
- Certificate validity: 1 year, renewable
- Certificate revocation via OCSP and CRL
- Certificate pinning recommended for client SDKs

**API Key (Secondary)**:
- API keys generated as cryptographically random 256-bit tokens
- Stored as SHA-256 hash in PostgreSQL
- Prefixed with `vts_live_` (production) or `vts_test_` (sandbox)
- Rotation: new key issued, old key valid for 24-hour overlap
- Compromised keys revoked immediately

### 3.2 Internal Authentication

**Service Mesh (Istio)**:
- All inter-service communication uses mTLS via Istio
- SPIFFE-based service identity (e.g., `spiffe://veritas.security/ns/production/sa/veritas-l1-scanner`)
- Automatic certificate rotation (24-hour lifetime)
- Authorization policies enforce service-to-service access rules

**Kubernetes RBAC**:
- Service accounts per workload
- No cluster-admin access for application service accounts
- Namespace-scoped roles
- Regular RBAC audit

### 3.3 Human Access

**Dashboard Authentication**:
- OIDC/OAuth 2.0 via identity provider (Okta, Auth0, Azure AD)
- MFA required for all users
- Session timeout: 8 hours
- RBAC roles: Viewer, Moderator, Admin, Compliance Officer

**Infrastructure Access**:
- No SSH access to production nodes (kubectl exec only, audited)
- Break-glass procedure for emergency access
- Privileged access management (PAM) for infrastructure operations
- All access logged and reviewed

---

## 4. Encryption Architecture

### 4.1 Encryption at Rest

| Data Store | Algorithm | Key Management |
|-----------|-----------|---------------|
| PostgreSQL | AES-256-GCM | AWS KMS / GCP KMS CMK |
| ClickHouse | AES-256-GCM | AWS KMS / GCP KMS CMK |
| Redis | AES-256 (EBS encryption) | AWS KMS |
| S3/GCS | AES-256-GCM (SSE-KMS) | Customer-managed CMK |
| Kafka (EBS) | AES-256 | AWS KMS |
| Backups | AES-256-GCM | Dedicated backup CMK |

### 4.2 Encryption in Transit

| Connection | Protocol | Minimum Version |
|-----------|----------|----------------|
| External API | TLS 1.3 | TLS 1.3 (no fallback) |
| Inter-service (Istio) | mTLS (TLS 1.3) | TLS 1.3 |
| Database connections | TLS 1.2+ | TLS 1.2 |
| Kafka inter-broker | TLS 1.2+ | TLS 1.2 |
| Redis cluster | TLS 1.2+ | TLS 1.2 |
| Cross-region replication | TLS 1.3 + VPN | TLS 1.3 |

### 4.3 Cipher Suites (External API)

```
TLS 1.3 only:
  TLS_AES_256_GCM_SHA384
  TLS_CHACHA20_POLY1305_SHA256
  TLS_AES_128_GCM_SHA256

Key Exchange: X25519, secp256r1
No TLS 1.2 fallback in production
```

---

## 5. Cryptographic Signing System

### 5.1 Key Hierarchy

```
Root Trust Anchor (offline, air-gapped)
├── Veritas Root CA Certificate (10-year validity)
│   ├── Regional Intermediate CA (EU-Central, 3-year validity)
│   │   ├── Signing Key (EU-Central, Q1 2026, 90-day rotation)
│   │   ├── Signing Key (EU-Central, Q2 2026, 90-day rotation)
│   │   └── ...
│   ├── Regional Intermediate CA (US-East, 3-year validity)
│   │   └── ...
│   └── Regional Intermediate CA (AP-East, 3-year validity)
│       └── ...
└── Tenant-Specific Signing Keys (per tenant, 90-day rotation)
```

### 5.2 HSM Configuration

**Hardware**: FIPS 140-2 Level 3 certified HSM
- AWS CloudHSM (primary) or Thales Luna HSM (on-premise option)
- Minimum 2 HSM instances per region (HA)
- Cross-region disaster recovery key backup

**Key Operations**:
- Key generation: Ed25519 (primary), RSA-4096 (legacy compatibility)
- Signing: Ed25519 sign operation (< 5ms per operation)
- Key export: Never (keys generated and used within HSM only)
- Key backup: Encrypted backup to DR HSM (same vendor)

### 5.3 Key Ceremony Procedure

1. **Preparation**: 5 key custodians identified, M-of-N threshold set (3 of 5)
2. **Ceremony Room**: Air-gapped workstation, no network connectivity, camera recording
3. **Key Generation**: Root CA generated on air-gapped HSM
4. **Secret Sharing**: Root key access split into 5 shares (Shamir's Secret Sharing)
5. **Distribution**: Each custodian receives one share in tamper-evident envelope
6. **Verification**: Root CA certificate exported and verified
7. **Intermediate CAs**: Generated on regional HSMs, signed by root
8. **Documentation**: Ceremony documented, signed by all custodians

### 5.4 Signature Verification (Public)

Any third party can verify a Veritas signature:

```
1. Retrieve public keys: GET https://api.veritas.security/.well-known/veritas-keys.json
2. Find key by key_id from the signed verdict
3. Compute SHA-512 hash of canonical JSON verdict
4. Verify Ed25519 signature against hash using public key
5. Verify certificate chain up to Veritas Root CA
6. Check key status via OCSP: GET https://ocsp.veritas.security/
```

---

## 6. Network Security

### 6.1 Network Segmentation

```
Internet → WAF/DDoS → Load Balancer → Public Subnet
                                          ↓ (only port 443)
                                    Application Subnet
                                          ↓ (specific ports only)
                                    Data Subnet
                                          ↓ (signer only)
                                    Security Subnet (HSM)

                        ════════════════════════
                        Sandbox Subnet (isolated, no connectivity)
```

### 6.2 Network Policies (Kubernetes)

```yaml
# Example: L2 Biometric pods can only talk to:
# - Kafka (consume/produce)
# - Scorer service (send results)
# - Prometheus (metrics scrape)
# DENIED: Internet, databases, HSM, dashboard, other services

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: veritas-l2-biometric
spec:
  podSelector:
    matchLabels:
      app: veritas-l2-biometric
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: prometheus
      ports:
        - port: 9090
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: kafka
      ports:
        - port: 9092
    - to:
        - podSelector:
            matchLabels:
              app: veritas-scorer
      ports:
        - port: 50051
    - to:  # DNS
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
```

### 6.3 DDoS Protection

| Layer | Protection | Provider |
|-------|-----------|---------|
| L3/L4 | Volumetric DDoS mitigation | AWS Shield Advanced / Cloudflare |
| L7 | Application-layer WAF rules | AWS WAF v2 / Cloudflare WAF |
| API | Rate limiting per tenant | Veritas gateway |
| API | Load shedding under extreme pressure | Veritas gateway |

### 6.4 Egress Control

- All production pods: No direct internet access
- Egress via NAT Gateway only for specific destinations:
  - Webhook delivery endpoints (tenant-provided URLs)
  - OCSP responders
  - Model download from S3 (internal endpoint)
- All other egress DENIED by default

---

## 7. Application Security

### 7.1 Secure Development Lifecycle

| Phase | Activity | Tool |
|-------|---------|------|
| Coding | Dependency vulnerability check | `cargo audit`, `pip-audit` |
| Coding | SAST (Static Analysis) | `cargo clippy`, `semgrep`, `bandit` |
| Build | Container image scanning | Trivy |
| Build | SBOM generation | Syft |
| Build | Reproducible builds | Docker BuildKit, cargo lock |
| Deploy | Image signature verification | Cosign (Sigstore) |
| Runtime | DAST (Dynamic Analysis) | OWASP ZAP (staging) |
| Runtime | Runtime security monitoring | Falco |

### 7.2 Container Security

- **Base images**: Distroless or Alpine (minimal attack surface)
- **Non-root**: All containers run as non-root user
- **Read-only filesystem**: `readOnlyRootFilesystem: true`
- **No privilege escalation**: `allowPrivilegeEscalation: false`
- **Capabilities dropped**: All capabilities dropped, only add specific ones if needed
- **Security context**: `runAsNonRoot: true`, `seccompProfile: RuntimeDefault`
- **Image provenance**: All images signed with Cosign before deployment

### 7.3 Memory Safety (Rust Services)

Rust provides memory safety guarantees that prevent:
- Buffer overflows
- Use-after-free
- Double-free
- Null pointer dereferences
- Data races

**Additional measures for biometric data**:
- Custom allocator for biometric data (securely zeroed on deallocation)
- No `unsafe` blocks in biometric processing code (enforced by lint)
- Stack-allocated biometric data where possible (automatic cleanup)

### 7.4 Input Validation

| Input | Validation |
|-------|-----------|
| Video data | File format verification, size limits, codec validation |
| API keys | Length check, format validation, hash comparison |
| Tenant IDs | UUID format validation |
| gRPC messages | Protobuf schema enforcement (automatic) |
| Webhook URLs | URL format validation, no internal IP addresses |
| Policy thresholds | Range validation (0.0 - 1.0) |
| Configuration values | Schema validation with defaults |

### 7.5 Secrets Management

| Secret Type | Storage | Rotation |
|-------------|---------|----------|
| HSM credentials | Kubernetes Secret (encrypted etcd) | Annual |
| Database passwords | AWS Secrets Manager | 90 days (automatic) |
| API keys | PostgreSQL (hashed) | On demand |
| TLS certificates | cert-manager (auto-renewal) | 90 days |
| Kafka credentials | AWS Secrets Manager | 90 days |
| Webhook HMAC secrets | PostgreSQL (encrypted) | On demand |

---

## 8. Supply Chain Security

### 8.1 Dependency Management

- **Lock files**: All dependencies pinned to exact versions (Cargo.lock, poetry.lock)
- **Vulnerability scanning**: Automated daily scanning of all dependencies
- **Update policy**: Security patches within 48 hours, minor updates weekly
- **Vendoring**: Critical dependencies vendored (offline build capability)

### 8.2 Build Pipeline Security

```
Source Code → Code Review (2 approvals) →
SAST Scan → Dependency Scan → Build →
Container Scan → Image Sign (Cosign) →
Deploy to Staging → DAST Scan →
Manual Approval → Deploy to Production
```

### 8.3 SBOM (Software Bill of Materials)

- Generated for every build using Syft
- Published to internal registry
- Includes: package name, version, license, hash
- Machine-readable format: SPDX and CycloneDX
- Retained for the lifetime of the release

---

## 9. Operational Security

### 9.1 Access Control Matrix

| Role | Production Cluster | Databases | HSM | Logs | Dashboard |
|------|-------------------|-----------|-----|------|-----------|
| SRE On-Call | Read pods/logs | Read-only | None | Full | Admin |
| Backend Dev | None | None | None | App logs only | Read |
| ML Engineer | GPU pods (read) | None | None | ML logs only | Read |
| Security Engineer | Read all | Read-only | Admin | Full | Admin |
| Compliance Officer | None | Compliance tables | None | Compliance logs | Read |
| Tenant Admin | None | Own tenant data only | None | Own tenant logs | Tenant admin |

### 9.2 Audit Logging

All security-relevant actions are logged to an immutable audit trail:

| Event | Logged Fields | Retention |
|-------|--------------|-----------|
| Authentication attempt | user/service, method, result, IP | 1 year |
| API request | tenant, endpoint, parameters (sanitized), result | 2 years |
| Policy change | tenant, old_value, new_value, changed_by | 10 years |
| Key operation | key_id, operation, performed_by | 10 years |
| Moderator action | reviewer, scan_id, original/new verdict, reason | 10 years |
| Infrastructure change | resource, action, performed_by | 1 year |
| Alert acknowledged | alert, acknowledged_by, timestamp | 1 year |

### 9.3 Security Monitoring

| Monitor | Tool | Alert On |
|---------|------|----------|
| Container runtime anomalies | Falco | Unexpected process execution, file access |
| Network anomalies | VPC Flow Logs + GuardDuty | Unusual traffic patterns, port scanning |
| API abuse patterns | WAF + custom rules | Credential stuffing, enumeration |
| Insider threat indicators | SIEM | Unusual data access patterns |
| Certificate transparency | CT log monitoring | Unauthorized certificate issuance |

---

## 10. Incident Response

### 10.1 Security Incident Classification

| Class | Description | Response Time | Example |
|-------|-------------|--------------|---------|
| S1 - Critical | Active data breach, system compromise | 15 minutes | Biometric data leak, HSM compromise |
| S2 - High | Vulnerability actively exploited | 1 hour | API authentication bypass |
| S3 - Medium | Vulnerability discovered, not exploited | 4 hours | Dependency CVE with CVSS > 7 |
| S4 - Low | Security improvement needed | Next sprint | Missing security header |

### 10.2 Security Incident Playbook

```
Detection → Triage → Containment → Investigation →
Remediation → Recovery → Post-Incident Review

For S1 (Critical):
  1. Alert: PagerDuty → Security Engineer + CTO
  2. Containment: Isolate affected systems (< 15 min)
  3. Assessment: Determine scope and data impact
  4. Notification: DPO notified (if biometric data involved)
  5. Legal: Legal counsel engaged (if data breach confirmed)
  6. GDPR: 72-hour DPA notification clock starts
  7. Remediation: Fix vulnerability, rotate credentials
  8. Recovery: Restore normal operations
  9. Review: Post-incident review within 48 hours
```

### 10.3 Breach Notification

| Stakeholder | Timeline | Method | Content |
|-------------|----------|--------|---------|
| Internal security team | Immediate | PagerDuty | Technical details |
| DPO | Within 1 hour | Phone + email | Impact assessment |
| Affected tenants | Within 24 hours | Encrypted email | Impact, actions taken |
| Data Protection Authority | Within 72 hours | Official channel | GDPR breach notification |
| Public (if required) | Per legal advice | Press release | Minimal, factual |

---

## 11. Compliance Certifications

### 11.1 Target Certifications

| Certification | Status | Target Date | Purpose |
|--------------|--------|-------------|---------|
| SOC 2 Type II | Planned | GA + 6 months | Enterprise customer requirement |
| ISO 27001 | Planned | GA + 12 months | International security standard |
| ISO 27701 | Planned | GA + 12 months | Privacy information management |
| EU AI Act Conformity | Required | Pre-GA | Legal requirement for high-risk AI |
| C5 (German cloud security) | Planned | GA + 9 months | German government/enterprise requirement |
| TISAX | Evaluated | GA + 12 months | Automotive industry requirement |

### 11.2 Continuous Compliance

- **Automated controls testing**: Weekly automated verification of security controls
- **Penetration testing**: Annual external penetration test + quarterly internal
- **Vulnerability management**: SLA for remediation based on CVSS score
  - Critical (9.0-10.0): 24 hours
  - High (7.0-8.9): 7 days
  - Medium (4.0-6.9): 30 days
  - Low (0.1-3.9): 90 days
