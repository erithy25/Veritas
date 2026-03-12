# Veritas B2B - API Specification

**Version**: 1.0.0
**Last Updated**: 2026-03-08
**Protocol**: gRPC (primary), REST (secondary)

---

## Table of Contents

1. [API Design Principles](#1-api-design-principles)
2. [Authentication & Authorization](#2-authentication--authorization)
3. [gRPC API (Primary)](#3-grpc-api-primary)
4. [REST API (Secondary)](#4-rest-api-secondary)
5. [Webhook API](#5-webhook-api)
6. [Error Handling](#6-error-handling)
7. [Rate Limiting](#7-rate-limiting)
8. [SDK Guidelines](#8-sdk-guidelines)

---

## 1. API Design Principles

1. **gRPC-First**: Primary API is gRPC for minimum latency and type safety between services
2. **REST Gateway**: REST API provided via gRPC-Gateway for clients that prefer HTTP/JSON
3. **Streaming Support**: Bidirectional gRPC streaming for large video uploads
4. **Idempotency**: All write operations are idempotent (safe to retry)
5. **Versioning**: API versioned via package namespace (v1, v2)
6. **Backward Compatibility**: New fields added to existing messages, never removed

---

## 2. Authentication & Authorization

### 2.1 Authentication Methods

| Method | Use Case | Details |
|--------|----------|---------|
| mTLS | Server-to-server integration | Client certificate issued per tenant |
| API Key | Simple integrations | SHA-256 hashed, passed in `x-api-key` header |
| JWT (OAuth 2.0) | Dashboard access | OIDC-compliant tokens with tenant claims |

### 2.2 mTLS Flow

```
1. Tenant receives client certificate during onboarding
2. Client presents certificate in TLS handshake
3. Gateway validates certificate against tenant CA
4. Tenant ID extracted from certificate CN/SAN
5. Request proceeds with authenticated tenant context
```

### 2.3 API Key Authentication

```
Header: x-api-key: vts_live_a1b2c3d4e5f6...
        x-tenant-id: 550e8400-e29b-41d4-a716-446655440000

Gateway validates:
1. Hash API key → compare against stored hash
2. Verify tenant_id matches API key's tenant
3. Check API key status (active, not revoked)
4. Apply tenant rate limits
```

### 2.4 Permissions Model

| Permission | Description |
|-----------|-------------|
| `analyze:sync` | Submit videos for synchronous analysis |
| `analyze:async` | Submit videos for asynchronous analysis |
| `results:read` | Read analysis results |
| `dashboard:read` | Access moderator dashboard (read-only) |
| `dashboard:moderate` | Perform moderation actions (override verdicts) |
| `policy:read` | Read tenant policy configuration |
| `policy:write` | Modify tenant policy configuration |
| `reports:read` | Access compliance reports |
| `sandbox:write` | Submit samples to red-team sandbox |

---

## 3. gRPC API (Primary)

### 3.1 Service Definition: VeritasAnalysis

```protobuf
syntax = "proto3";
package veritas.api.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/duration.proto";

// Primary analysis service
service VeritasAnalysis {
  // Synchronous analysis - returns verdict after full analysis
  rpc AnalyzeVideo (AnalyzeVideoRequest) returns (AnalyzeVideoResponse);

  // Streaming upload for large videos
  rpc AnalyzeVideoStream (stream VideoChunk) returns (AnalyzeVideoResponse);

  // Asynchronous analysis - returns immediately, delivers result via webhook
  rpc AnalyzeVideoAsync (AnalyzeVideoRequest) returns (AsyncAnalysisResponse);

  // Check status of async analysis
  rpc GetAnalysisStatus (GetAnalysisStatusRequest) returns (AnalysisStatus);

  // Retrieve a previous analysis result
  rpc GetVerdict (GetVerdictRequest) returns (SignedVerdict);

  // Stream of real-time verdicts (for dashboard integration)
  rpc StreamVerdicts (StreamVerdictsRequest) returns (stream SignedVerdict);
}

// --- Request Messages ---

message AnalyzeVideoRequest {
  // Unique upload ID from the platform (idempotency key)
  string upload_id = 1;

  // Video data (for non-streaming uploads, max 500MB)
  bytes video_data = 2;

  // Video metadata provided by the platform
  VideoMetadata metadata = 3;

  // Analysis configuration overrides
  AnalysisConfig config = 4;
}

message VideoChunk {
  // Upload ID (must be same across all chunks)
  string upload_id = 1;

  // Chunk sequence number (0-indexed)
  uint32 chunk_index = 2;

  // Total number of chunks
  uint32 total_chunks = 3;

  // Chunk data
  bytes data = 4;

  // Metadata (only required in first chunk)
  VideoMetadata metadata = 5;
}

message VideoMetadata {
  // Original filename (optional)
  string filename = 1;

  // MIME type
  string content_type = 2;

  // Duration in seconds (if known)
  float duration_seconds = 3;

  // Resolution (e.g., "1920x1080")
  string resolution = 4;

  // Platform-specific context
  map<string, string> platform_context = 5;

  // Account trust score from platform (0.0 - 1.0, optional)
  optional float account_trust_score = 6;

  // Content category from platform (optional)
  string content_category = 7;
}

message AnalysisConfig {
  // Maximum detection tier (1, 2, or 3). Default: 3
  optional uint32 max_tier = 1;

  // Priority level (LOW, NORMAL, HIGH, CRITICAL)
  optional Priority priority = 2;

  // Webhook URL for async result delivery
  string webhook_url = 3;

  // Whether to include C2PA manifest in response
  optional bool include_c2pa = 4;

  // Whether to include XAI explanations in response
  optional bool include_explanations = 5;
}

enum Priority {
  PRIORITY_LOW = 0;
  PRIORITY_NORMAL = 1;
  PRIORITY_HIGH = 2;
  PRIORITY_CRITICAL = 3;
}

// --- Response Messages ---

message AnalyzeVideoResponse {
  // Signed verdict with full details
  SignedVerdict verdict = 1;

  // C2PA manifest (if requested)
  optional bytes c2pa_manifest = 2;

  // Processing statistics
  ProcessingStats stats = 3;
}

message AsyncAnalysisResponse {
  // Scan ID for status checks
  string scan_id = 1;

  // Estimated completion time
  google.protobuf.Timestamp estimated_completion = 2;

  // Status check endpoint
  string status_url = 3;
}

message SignedVerdict {
  // Unique scan identifier
  string scan_id = 1;

  // Upload ID from request
  string upload_id = 2;

  // Final verdict
  Verdict verdict = 3;

  // Risk score (0.0 - 1.0)
  float risk_score = 4;

  // Detailed detection results per tier
  DetectionResults detection_results = 5;

  // XAI reason codes and explanations
  repeated ReasonCode reason_codes = 6;

  // Context analysis results
  ContextAnalysis context = 7;

  // Cryptographic signature
  Signature signature = 8;

  // Timestamps
  google.protobuf.Timestamp analyzed_at = 9;

  // Model versions used
  map<string, string> model_versions = 10;

  // Processing region (for data residency verification)
  string processing_region = 11;
}

enum Verdict {
  VERDICT_UNSPECIFIED = 0;
  VERDICT_ALLOW = 1;
  VERDICT_FLAG = 2;
  VERDICT_FLAG_URGENT = 3;
  VERDICT_BLOCK = 4;
}

message DetectionResults {
  // L1 results
  L1Result l1 = 1;

  // L2 results (if performed)
  optional L2Result l2 = 2;

  // L3 results (if performed)
  optional L3Result l3 = 3;

  // Highest tier that was executed
  uint32 highest_tier = 4;
}

message L1Result {
  bool hash_match = 1;
  string hash_match_id = 2;
  float metadata_score = 3;
  float compression_score = 4;
  optional bool c2pa_valid = 5;
  repeated string detected_tools = 6;
  uint32 duration_ms = 7;
}

message L2Result {
  float flicker_score = 1;
  float rppg_score = 2;
  float rppg_quality = 3;
  float eye_movement_score = 4;
  float skin_texture_score = 5;
  uint32 faces_analyzed = 6;
  uint32 duration_ms = 7;
}

message L3Result {
  float vit_score = 1;
  float efficientnet_score = 2;
  float tcn_score = 3;
  float diffusion_score = 4;
  float lipsync_score = 5;
  float ensemble_score = 6;
  float model_agreement = 7;
  uint32 duration_ms = 8;
}

message ReasonCode {
  // Machine-readable code (e.g., "BIO_RPPG_ABSENT")
  string code = 1;

  // Category (L1_METADATA, L2_BIOMETRIC, L3_NEURAL, CONTEXT)
  string category = 2;

  // Human-readable explanation
  string explanation = 3;

  // Confidence for this specific signal (0.0 - 1.0)
  float confidence = 4;

  // Localized explanation (ISO 639-1 language code → text)
  map<string, string> localized_explanations = 5;
}

message ContextAnalysis {
  bool public_figure_detected = 1;
  float public_figure_confidence = 2;
  float political_context_score = 3;
  float account_trust_score = 4;
}

message Signature {
  // Ed25519 signature bytes
  bytes signature_bytes = 1;

  // Key ID used for signing
  string key_id = 2;

  // Signing algorithm
  string algorithm = 3;

  // URL to retrieve the public key / certificate chain
  string cert_chain_url = 4;

  // SHA-512 hash of the signed content
  bytes content_hash = 5;

  // Signing timestamp
  google.protobuf.Timestamp signed_at = 6;
}

message ProcessingStats {
  uint32 total_duration_ms = 1;
  uint32 frames_extracted = 2;
  uint32 faces_detected = 3;
  repeated uint32 tiers_used = 4;
  string edge_node = 5;
  string analysis_region = 6;
}

// --- Status Check ---

message GetAnalysisStatusRequest {
  string scan_id = 1;
}

message AnalysisStatus {
  string scan_id = 1;
  Status status = 2;
  float progress = 3; // 0.0 - 1.0
  string current_stage = 4; // "L1", "L2", "L3", "SCORING", "SIGNING"
  google.protobuf.Timestamp estimated_completion = 5;
  optional SignedVerdict verdict = 6; // Set when status = COMPLETED
}

enum Status {
  STATUS_UNSPECIFIED = 0;
  STATUS_QUEUED = 1;
  STATUS_PROCESSING = 2;
  STATUS_COMPLETED = 3;
  STATUS_FAILED = 4;
}

// --- Verdict Retrieval ---

message GetVerdictRequest {
  oneof identifier {
    string scan_id = 1;
    string upload_id = 2;
  }
}

// --- Streaming ---

message StreamVerdictsRequest {
  // Filter by verdict type (empty = all)
  repeated Verdict verdict_filter = 1;

  // Filter by minimum risk score
  optional float min_risk_score = 2;

  // Include XAI explanations in stream
  bool include_explanations = 3;
}
```

### 3.2 Service Definition: VeritasDashboard

```protobuf
// Dashboard and moderation service
service VeritasDashboard {
  // Get paginated list of flagged content
  rpc ListFlaggedContent (ListFlaggedContentRequest) returns (ListFlaggedContentResponse);

  // Get detailed verdict with XAI explanations
  rpc GetVerdictDetail (GetVerdictDetailRequest) returns (VerdictDetail);

  // Override a verdict (human moderation)
  rpc OverrideVerdict (OverrideVerdictRequest) returns (OverrideVerdictResponse);

  // Get analytics data
  rpc GetAnalytics (GetAnalyticsRequest) returns (AnalyticsResponse);

  // Get tenant policy
  rpc GetPolicy (GetPolicyRequest) returns (PolicyResponse);

  // Update tenant policy
  rpc UpdatePolicy (UpdatePolicyRequest) returns (PolicyResponse);
}

message OverrideVerdictRequest {
  string scan_id = 1;
  Verdict new_verdict = 2;
  string reason = 3; // Mandatory reason for override
  string reviewer_id = 4;
}

message OverrideVerdictResponse {
  string scan_id = 1;
  Verdict original_verdict = 2;
  Verdict new_verdict = 3;
  google.protobuf.Timestamp overridden_at = 4;
  string audit_trail_id = 5;
}
```

### 3.3 Service Definition: VeritasCompliance

```protobuf
// Compliance and reporting service
service VeritasCompliance {
  // Generate compliance report
  rpc GenerateReport (GenerateReportRequest) returns (ReportResponse);

  // Get report status
  rpc GetReportStatus (GetReportStatusRequest) returns (ReportStatus);

  // Download generated report
  rpc DownloadReport (DownloadReportRequest) returns (stream ReportChunk);

  // Verify a signed verdict (public endpoint)
  rpc VerifySignature (VerifySignatureRequest) returns (VerifySignatureResponse);
}

message GenerateReportRequest {
  ReportType report_type = 1;
  google.protobuf.Timestamp period_start = 2;
  google.protobuf.Timestamp period_end = 3;
  OutputFormat format = 4;
}

enum ReportType {
  REPORT_EU_AI_ACT_MONTHLY = 0;
  REPORT_GDPR_QUARTERLY = 1;
  REPORT_DSA_TRANSPARENCY = 2;
  REPORT_INTERNAL_AUDIT = 3;
  REPORT_TENANT_SUMMARY = 4;
}

enum OutputFormat {
  FORMAT_PDF = 0;
  FORMAT_JSON = 1;
  FORMAT_CSV = 2;
}

message VerifySignatureRequest {
  // The signed verdict to verify
  SignedVerdict verdict = 1;
}

message VerifySignatureResponse {
  bool valid = 1;
  string key_id = 2;
  string key_status = 3; // 'ACTIVE', 'ROTATED', 'REVOKED'
  google.protobuf.Timestamp key_valid_until = 4;
}
```

### 3.4 Service Definition: VeritasSandbox

```protobuf
// Red-team sandbox service
service VeritasSandbox {
  // Submit adversarial sample for testing
  rpc SubmitSample (SubmitSampleRequest) returns (SubmitSampleResponse);

  // Get analysis result for submitted sample
  rpc GetSampleResult (GetSampleResultRequest) returns (SampleResult);

  // Submit batch of adversarial samples
  rpc SubmitBatch (stream SubmitSampleRequest) returns (BatchResponse);

  // Get session attack report
  rpc GetAttackReport (GetAttackReportRequest) returns (AttackReport);

  // Get current model info in sandbox
  rpc GetModelInfo (GetModelInfoRequest) returns (ModelInfoResponse);

  // Get sandbox metrics
  rpc GetSandboxMetrics (GetSandboxMetricsRequest) returns (SandboxMetrics);
}
```

---

## 4. REST API (Secondary)

REST API provided via gRPC-Gateway for clients preferring HTTP/JSON.

### 4.1 Endpoint Mapping

| gRPC Method | REST Endpoint | HTTP Method |
|------------|---------------|-------------|
| `AnalyzeVideo` | `/v1/analyze` | POST |
| `AnalyzeVideoAsync` | `/v1/analyze/async` | POST |
| `GetAnalysisStatus` | `/v1/analyze/{scan_id}/status` | GET |
| `GetVerdict` | `/v1/verdicts/{scan_id}` | GET |
| `ListFlaggedContent` | `/v1/dashboard/flagged` | GET |
| `GetVerdictDetail` | `/v1/dashboard/verdicts/{scan_id}` | GET |
| `OverrideVerdict` | `/v1/dashboard/verdicts/{scan_id}/override` | POST |
| `GetAnalytics` | `/v1/dashboard/analytics` | GET |
| `GetPolicy` | `/v1/policy` | GET |
| `UpdatePolicy` | `/v1/policy` | PUT |
| `GenerateReport` | `/v1/compliance/reports` | POST |
| `GetReportStatus` | `/v1/compliance/reports/{report_id}` | GET |
| `VerifySignature` | `/v1/verify` | POST |
| `SubmitSample` | `/v1/sandbox/samples` | POST |

### 4.2 REST Request/Response Examples

**POST /v1/analyze**

Request:
```json
{
  "upload_id": "plat-upload-2026-abc123",
  "video_data": "<base64-encoded video>",
  "metadata": {
    "content_type": "video/mp4",
    "duration_seconds": 30.5,
    "resolution": "1920x1080",
    "account_trust_score": 0.85
  },
  "config": {
    "max_tier": 3,
    "priority": "PRIORITY_NORMAL",
    "include_c2pa": true,
    "include_explanations": true
  }
}
```

Response (200 OK):
```json
{
  "verdict": {
    "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "upload_id": "plat-upload-2026-abc123",
    "verdict": "VERDICT_FLAG",
    "risk_score": 0.72,
    "detection_results": {
      "l1": {
        "hash_match": false,
        "metadata_score": 0.15,
        "compression_score": 0.22,
        "c2pa_valid": null,
        "detected_tools": [],
        "duration_ms": 4
      },
      "l2": {
        "flicker_score": 0.68,
        "rppg_score": 0.81,
        "rppg_quality": 0.92,
        "eye_movement_score": 0.34,
        "skin_texture_score": 0.45,
        "faces_analyzed": 1,
        "duration_ms": 87
      },
      "l3": {
        "vit_score": 0.73,
        "efficientnet_score": 0.69,
        "tcn_score": 0.77,
        "diffusion_score": 0.12,
        "lipsync_score": 0.65,
        "ensemble_score": 0.72,
        "model_agreement": 0.78,
        "duration_ms": 412
      },
      "highest_tier": 3
    },
    "reason_codes": [
      {
        "code": "BIO_RPPG_SYNC_FAIL",
        "category": "L2_BIOMETRIC",
        "explanation": "Blood flow signals in left and right cheek are anti-correlated (r=-0.7)",
        "confidence": 0.81
      },
      {
        "code": "DNN_TEMPORAL_INCONSIST",
        "category": "L3_NEURAL",
        "explanation": "Inter-frame face geometry varies beyond natural range (3.2x std deviation)",
        "confidence": 0.77
      }
    ],
    "context": {
      "public_figure_detected": false,
      "political_context_score": 0.05,
      "account_trust_score": 0.85
    },
    "signature": {
      "key_id": "veritas-eu-central-2026-q1",
      "algorithm": "Ed25519",
      "cert_chain_url": "https://api.veritas.security/.well-known/veritas-keys.json",
      "signed_at": "2026-03-08T14:23:45.678Z"
    },
    "model_versions": {
      "vit": "v1.4.2",
      "efficientnet": "v2.1.0",
      "tcn": "v1.2.3"
    },
    "processing_region": "eu-central-1"
  },
  "stats": {
    "total_duration_ms": 503,
    "frames_extracted": 31,
    "faces_detected": 1,
    "tiers_used": [1, 2, 3],
    "analysis_region": "eu-central-1"
  }
}
```

---

## 5. Webhook API

### 5.1 Webhook Delivery (Async Results)

When async analysis completes, Veritas delivers results via webhook:

```
POST {webhook_url}
Content-Type: application/json
X-Veritas-Signature: sha256=<HMAC-SHA256 of body using webhook secret>
X-Veritas-Timestamp: 2026-03-08T14:23:45.678Z
X-Veritas-Event: analysis.completed

{
  "event": "analysis.completed",
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "upload_id": "plat-upload-2026-abc123",
  "verdict": { ... } // Same as AnalyzeVideoResponse
}
```

### 5.2 Webhook Security

- **HMAC Signature**: Every webhook payload signed with tenant-specific secret
- **Timestamp Validation**: Reject webhooks with timestamp > 5 minutes old
- **Retry Policy**: 3 retries with exponential backoff (1s, 10s, 60s)
- **Timeout**: 10-second response timeout per delivery attempt
- **IP Allowlist**: Webhook requests originate from published IP ranges

---

## 6. Error Handling

### 6.1 gRPC Error Codes

| gRPC Code | HTTP Status | Usage |
|-----------|-------------|-------|
| `OK` | 200 | Success |
| `INVALID_ARGUMENT` | 400 | Invalid request parameters |
| `UNAUTHENTICATED` | 401 | Missing or invalid credentials |
| `PERMISSION_DENIED` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Scan/verdict not found |
| `ALREADY_EXISTS` | 409 | Duplicate upload_id (idempotent) |
| `RESOURCE_EXHAUSTED` | 429 | Rate limit exceeded |
| `INTERNAL` | 500 | Internal server error |
| `UNAVAILABLE` | 503 | Service temporarily unavailable |
| `DEADLINE_EXCEEDED` | 504 | Analysis timeout |

### 6.2 Error Response Format

```json
{
  "error": {
    "code": "RESOURCE_EXHAUSTED",
    "message": "Rate limit exceeded. Current limit: 1000 requests/second",
    "details": {
      "retry_after_seconds": 2,
      "current_rate": 1247,
      "limit": 1000,
      "tenant_id": "550e8400-..."
    }
  }
}
```

---

## 7. Rate Limiting

### 7.1 Rate Limit Headers

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 750
X-RateLimit-Reset: 1709912630
X-RateLimit-Window: 1s
```

### 7.2 Rate Limit Tiers

| Tier | Requests/Second | Requests/Day | Concurrent L3 |
|------|----------------|-------------|----------------|
| Starter | 100 | 500,000 | 10 |
| Professional | 1,000 | 10,000,000 | 100 |
| Enterprise | 10,000 | 100,000,000 | 1,000 |
| Platform | 100,000 | Unlimited | 10,000 |

---

## 8. SDK Guidelines

### 8.1 SDK Features (all languages)

- Connection management with automatic reconnection
- Retry logic with exponential backoff and jitter
- Streaming upload support with progress callbacks
- Signature verification utility
- Rate limit handling (automatic backoff)
- Comprehensive error types
- OpenTelemetry tracing integration
- Async/sync variants

### 8.2 Available SDKs

| Language | Package Name | Primary Use Case |
|----------|-------------|-----------------|
| Rust | `veritas-client` | High-performance platform backends |
| Python | `veritas-sdk` | ML pipelines, scripting, testing |
| Go | `veritas-go` | Go-based platform backends |
| Java/Kotlin | `com.veritas:veritas-sdk` | JVM-based platforms, Android |
| TypeScript | `@veritas/sdk` | Node.js backends, dashboard integration |
