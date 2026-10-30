# Security Assessment Report

**System Name:** CampusShield API Gateway & Request Storm Shield  
**Project ID:** Cybersecurity Project 09 · Stop the Request Storm  
**Program:** BMSCE × MindMatrix Skill Lab Initiative  
**Assessment Period:** October 28 – October 30, 2026  
**Assessment Team:** Team 9 (Security Architect; Cloud Security Engineer; Application Security Engineer; Identity & Data Security Engineer; Detection, Testing & Evidence Engineer)  
**Target Environments:** Local ASGI Sandbox, Docker Container, Google Cloud Run  

---

## 1. Executive Summary

CampusShield is a defensive API security gateway designed to protect campus and student service APIs from volumetric request storms, denial-of-service (DoS) attacks, boundary burst exploitation, and backend resource starvation.

Prior to remediation, baseline vulnerability assessment revealed that unshielded APIs accepted unbounded bursts of requests without rate limiting or admission gating. During simulated 150 RPS storm traffic, the backend mock service experienced severe latency degradation (from 20ms baseline to >2000ms) and connection pool saturation, dropping legitimate requests. Furthermore, callers could exhaust server memory through high-cardinality API key forging, and telemetry streams leaked raw IP addresses.

To remediate these risks, the team implemented a defense-in-depth architecture featuring:
1. **Multi-Algorithm Rate Limiting:** High-performance Token Bucket, Sliding Window Counter, and Leaky Bucket Queue Shaper strategies.
2. **Tiered Identity & Cardinality Gating:** Strict validation of API key tiers (Free 1x, Pro 5x, Enterprise 20x) with unknown keys falling back to the client IP bucket to prevent cardinality explosion.
3. **Adaptive Storm Defense:** Real-time velocity detection (5s rolling window) that automatically tightens unauthenticated limits during active attacks while preserving capacity for prioritized tiers.
4. **Stale-While-Revalidate (SWR) Graceful Degradation:** Serves cached snapshots (`200 Cached-Fallback`) for read routes under congestion rather than failing with 429 errors.
5. **Structured Audit Logging & Data Minimization:** Conforming to Google Cloud Logging specification with correlation IDs, masked IPs (`*.*`), masked API keys, and safe error handling that never exposes server internals.

**Release Recommendation:**  
**CONDITIONAL RELEASE (GO WITH CONDITIONS)**. All 8 mandated test matrix verification cases (T01–T08) passed (100% pass rate), all 6 identified security findings were remediated, and zero plain secrets or credentials exist in the codebase. Production rollout is approved subject to running multi-instance deployments behind a distributed cache (e.g., Cloud Firestore / Redis) as documented in Section 6.

---

## 2. System Overview

### 2.1 Purpose & Core Components
CampusShield sits as a high-performance reverse-proxy and ASGI middleware directly in front of internal campus microservices. Its core components include:
- **ShieldMiddleware:** Pure ASGI non-blocking middleware intercepting all HTTP traffic, resolving caller sessions, extracting correlation IDs, and evaluating rate limit policies.
- **Storage State Engines:** Atomic, lock-synchronized state stores supporting in-memory storage (primary default), Redis (optional plugin), and Google Cloud Firestore (cloud adapter).
- **Session Isolation Manager:** Multi-tenant sandbox isolating each browser or testing client into an independent state container (`SessionState`) keyed by cryptographically secure tokens.
- **Metrics Ring Buffers:** Low-overhead 120-second circular buffers tracking throughput, status codes, p50/p95 latency percentiles, and blocked identity frequency.
- **Structured Cloud Logging Adapter:** Formats security events according to Google Cloud Logging schemas with automatic privacy scrubbing.

### 2.2 Data Flow & Trust Boundaries
```text
[External Untrusted Client]
           │
     (HTTP Request + X-API-Key / Session Cookie)
           ▼
[Edge / Reverse Proxy (Cloud Run)]
           │
           ▼
[ShieldMiddleware Perimeter]
   ├── 1. Extract/Generate Correlation ID (X-Correlation-Id)
   ├── 2. Resolve Client Identity & Tier (Key Registry -> IP Fallback)
   ├── 3. Evaluate Adaptive Storm Gate & Global Upstream Cap
   ├── 4. Execute Limiter Strategy (Token Bucket / Sliding Window / Leaky Bucket)
   ├── 5. On Allowed -> Forward to Core API -> Return 200 + RateLimit Headers
   ├── 6. On Throttled (GET Read) -> Return 200 Cached-Fallback (SWR)
   └── 7. On Throttled (POST Write) -> Return 429 Too Many Requests + Retry-After
           │
           ├── Emit Structured Event -> [Google Cloud Logging / Audit Log]
           └── Update Telemetry -> [Google Cloud Monitoring / Ring Buffer]
```

**Trust Boundary Analysis:**
- **Boundary A (Internet to Gateway):** Untrusted. All headers except internal connection sockets are treated as hostile. `X-Forwarded-For` is only respected when received from trusted loopback or reverse proxy interfaces.
- **Boundary B (Gateway to Upstream Core Services):** Protected internal network. Upstream services assume traffic arriving through the gateway has been sanitized, metered, and admitted under safe concurrency bounds.
- **Boundary C (Gateway to Observability Channels):** Confidential audit domain. Strict data minimization ensures that no sensitive payload bodies, authentication keys, or unmasked IPs cross into logs or telemetry feeds.

---

## 3. Findings Register

The table below summarizes all security weaknesses identified during the baseline assessment, along with their assigned severities, implemented remediations, and retest outcomes.

| ID | Finding Description | Severity | Impact | Remediation Applied | Retest Outcome | Evidence Reference |
|---|---|---|---|---|---|---|
| **FR-01** | **Unchecked Volumetric Request Storm**<br>Baseline service allowed unrestricted request bursts. | **High** | Attackers could flood API endpoints, overwhelming mock upstream workers and causing denial of service. | Implemented pure ASGI `ShieldMiddleware` with Token Bucket, Sliding Window, and Leaky Bucket algorithms. | **REMEDIATED** (Pass) | [evidence/baseline_assessment.log](file:///a:/Cybersec/evidence/baseline_assessment.log)<br>[evidence/T02_requests_above_threshold_rejected.log](file:///a:/Cybersec/evidence/T02_requests_above_threshold_rejected.log) |
| **FR-02** | **Cardinality Abuse via Random API Keys**<br>System allowed arbitrary API key headers to instantiate buckets. | **High** | High-cardinality attacker floods could consume gigabytes of memory, inducing Out-Of-Memory (OOM) crashes. | Restricted tier allocation to validated `DEMO_KEY_REGISTRY`. Unrecognized keys fall back strictly to the client IP bucket. | **REMEDIATED** (Pass) | [tests/test_middleware.py](file:///a:/Cybersec/tests/test_middleware.py#L54-L65) |
| **FR-03** | **Boundary Double-Burst Exploitation**<br>Fixed-window counters allowed 2x capacity bursts across window edges. | **Medium** | Callers could send 10 requests at t=0.99s and 10 requests at t=1.01s, doubling permitted traffic rates. | Implemented Sliding Window Counter using sub-window weighted estimation to prevent edge bursts. | **REMEDIATED** (Pass) | [tests/test_sliding_window.py](file:///a:/Cybersec/tests/test_sliding_window.py#L35-L65) |
| **FR-04** | **Unconditional Read Request Drops During Surges**<br>Read-only traffic was rejected with 429 during transient surges. | **Medium** | Student users could not access cached course announcements or read analytics during high registration traffic. | Added Stale-While-Revalidate (SWR) Graceful Degradation cache, serving cached responses (`200 Cached-Fallback`). | **REMEDIATED** (Pass) | [tests/test_middleware.py](file:///a:/Cybersec/tests/test_middleware.py#L68-L89) |
| **FR-05** | **Plaintext IP and Token Exposure in Logs**<br>Raw client IPs and API tokens appeared in plain text in logs and dashboard. | **Medium** | Exposed student network origins and internal key identifiers during live demonstrations or log sharing. | Added `mask_identity` scrubber (masking IPv4 to `*.*` and keys to `API_KEY [TIER]`) and recursive payload sanitization. | **REMEDIATED** (Pass) | [evidence/T05_structured_security_events.log](file:///a:/Cybersec/evidence/T05_structured_security_events.log)<br>[evidence/T07_secret_and_pii_audit.log](file:///a:/Cybersec/evidence/T07_secret_and_pii_audit.log) |
| **FR-06** | **Unhandled Exceptions Leaking Server Internals**<br>Internal errors returned default stack traces. | **Low** | Leaked internal file structures, Python module versions, and component class names to external callers. | Implemented safe exception handling in middleware, returning clean HTTP 500 JSON with correlation ID and logging structured event. | **REMEDIATED** (Pass) | [evidence/T06_controlled_error_handling.log](file:///a:/Cybersec/evidence/T06_controlled_error_handling.log) |

---

## 4. Controls Implemented

### 4.1 Defensive Rate Limiting Algorithms
- **Token Bucket:** Continuously refills tokens at rate $r$. When a request arrives with cost $c$, tokens are deducted if available; otherwise rejected. Burst capacity allows controlled spikes up to bucket capacity $C$.
- **Sliding Window Counter:** Approximates requests in a rolling window of length $W$ using current and previous window counts:
  $$\text{Estimated Count} = \text{Count}_{\text{prev}} \times \left(1 - \frac{t_{\text{elapsed}}}{W}\right) + \text{Count}_{\text{curr}}$$
- **Leaky Bucket / Queue Shaper:** Treats request processing as a constant outflow stream. Requests arriving in bursts are virtually scheduled with bounded queue delays, smoothing traffic.

### 4.2 Adaptive Storm Gate
The storm detector monitors a 5-second sliding window of aggregate traffic. If aggregate velocity exceeds `storm_rps_threshold` (100 RPS) or distinct blocked identities exceed `storm_ip_threshold` (50), storm mode triggers:
- Anonymous and Free-tier quotas are tightened by 50% (`storm_tighten_factor = 0.5`).
- Priority tiers (Pro and Enterprise) maintain unthrottled access.
- Global admission cap sheds excess volume before reaching upstream workers.

### 4.3 Structured Security Logging & Telemetry
Every inbound request generates an audit record conforming to Google Cloud Logging:
- **Correlation Tracking:** Injects and returns `X-Correlation-Id` across all responses.
- **Zero-Secret Guarantee:** Strips authorization headers, tokens, and cookies from log output.
- **Privacy Masking:** Maps `198.51.100.45` -> `198.51.*.*` and `pro-demo-key` -> `API_KEY [PRO]`.

---

## 5. Test Results (Required Test Matrix T01 – T08)

All 8 tests specified in Section 8 of the Project Guide were executed using automated Pytest assertions:

| ID | Test Case | Expected Result After Fix | Observed Result | Status | Evidence Filename |
|---|---|---|---|---|---|
| **T01** | Requests below threshold succeed. | Documented expected behaviour; requests accepted, tokens decremented, rate limit headers and correlation ID returned. | 5 requests to `/api/ping` returned HTTP 200, decrementing remaining quota from 9 to 5. `X-Correlation-Id` and `X-Ratelimit-*` verified. | **PASS** | [evidence/T01_requests_below_threshold.log](file:///a:/Cybersec/evidence/T01_requests_below_threshold.log) |
| **T02** | Requests above threshold are rejected consistently. | Once quota is exhausted, subsequent non-cacheable / write requests return HTTP 429 with integer `Retry-After`. | Calling `/api/heavy-compute` (cost 5) twice consumed 10 tokens. Subsequent calls strictly returned HTTP 429 with `Retry-After: 3` and remaining 0. | **PASS** | [evidence/T02_requests_above_threshold_rejected.log](file:///a:/Cybersec/evidence/T02_requests_above_threshold_rejected.log) |
| **T03** | Limiter resets according to its documented window. | Bucket refills continuously at `base_refill_rate` tokens per second over elapsed time. | At capacity exhaustion, after a 1.05s wait with refill rate 4.0 tokens/s, the bucket refilled to 3 tokens, restoring admission. | **PASS** | [evidence/T03_limiter_window_reset.log](file:///a:/Cybersec/evidence/T03_limiter_window_reset.log) |
| **T04** | Valid requests resume after the limit window. | Legitimate client requests resume normal operation (HTTP 200) once cooldown window expires. | Following cooldown period, calling `/api/ping` succeeded immediately with HTTP 200 and standard payload. | **PASS** | [evidence/T04_valid_requests_resume.log](file:///a:/Cybersec/evidence/T04_valid_requests_resume.log) |
| **T05** | Logs/metrics show decisions without sensitive data. | Event type, timestamp, outcome, correlation ID recorded. No raw keys, passwords, or unmasked IPs. | Structured audit logs verified: IPs masked to `198.51.*.*`, API keys labeled `API_KEY [PRO]`, passwords replaced with `[REDACTED]`. | **PASS** | [evidence/T05_structured_security_events.log](file:///a:/Cybersec/evidence/T05_structured_security_events.log) |
| **T06** | Trigger a controlled unexpected error. | Safe response (HTTP 500, generic message, correlation ID, no stack trace); useful security event recorded. | `GET /api/controlled-error` returned clean JSON with `correlation_id: corr-audit-t06-demo`. Structured error event logged with severity ERROR. | **PASS** | [evidence/T06_controlled_error_handling.log](file:///a:/Cybersec/evidence/T06_controlled_error_handling.log) |
| **T07** | Inspect source, output and logs for sensitive data. | No private keys, cloud tokens, production passwords, or real student data in code, logs, or responses. | Regex scanner inspected 25+ files. Zero RSA keys, AWS/GCP real tokens, or personal identifiers found. All demo data strictly synthetic. | **PASS** | [evidence/T07_secret_and_pii_audit.log](file:///a:/Cybersec/evidence/T07_secret_and_pii_audit.log) |
| **T08** | Repeat the complete test set. | Complete test matrix executes deterministically and repeatedly with 100% reproducible results. | Full pytest suite ran: 30 passed, 1 skipped (offline Redis). Verified deterministic test repeatability across all test modules. | **PASS** | [evidence/T08_reproducible_test_run.log](file:///a:/Cybersec/evidence/T08_reproducible_test_run.log) |

---

## 6. Limitations & Assumptions

In accordance with the BMSCE x MindMatrix Environment Caveat:
1. **Single-Worker In-Memory State:** By default, state is maintained in-process with asynchronous lock synchronization (`--workers 1`). In multi-container deployments (e.g. horizontally autoscaled Cloud Run instances), instances require a shared distributed backing store (Google Cloud Firestore or Redis) to share bucket state across instances.
2. **Local vs Cloud Service Adapters:** Cloud Logging and Cloud Monitoring adapters export standard JSON payloads conforming to GCP schemas. In environments without active GCP service credentials, these adapters transparently route to local ring buffers and stdout to ensure full local testability.
3. **Synthetic Attack Simulation:** The Attack Simulator runs loopback HTTP synthetic workloads (`normal`, `ddos`, `exhaustion`, `botnet`) within isolated session containers. Real-world distributed attacks would traverse external CDNs and Web Application Firewalls (WAF) prior to reaching the gateway.

---

## 7. Conclusion & Next Steps

The CampusShield API Under Attack mitigation project has successfully satisfied all core specifications:
- **Defensive Workflow Demonstrated:** Unshielded baseline failure reproduced, multi-algorithm defense controls implemented, and post-remediation resilience verified.
- **Zero Sensitive Data Leakage:** Zero credentials or unmasked personal data exist in code, logs, or evidence.
- **Traceable Verification:** All tests are fully automated, reproducible, and supported by timestamped evidence logs.

**Next Steps Prior to Production Deployment:**
1. Connect Google Cloud Firestore client credentials in staging to validate cross-region bucket synchronization under horizontal autoscaling.
2. Configure Google Cloud Monitoring alert policies on metric `custom.googleapis.com/ratelimit/blocked_count` to trigger PagerDuty notifications when storm mode persists for >60 seconds.
3. Integrate with Cloud Armor / Cloudflare WAF to drop malicious IP subnets before traffic enters application containers.
