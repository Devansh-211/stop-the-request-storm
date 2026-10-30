# 🛡️ CampusShield — Stop the Request Storm (Team 9)

**BMSCE × MindMatrix Skill Lab Initiative**  
**Cybersecurity Project 09 · Student Instructional Implementation**  
*Simulate a burst of API requests and implement application-level rate limiting, request rejection, and security logging.*

---

## 📋 Project Summary & Overview

CampusShield is an enterprise-grade defensive API gateway, multi-algorithm rate limiter, adaptive storm shield, and dark cyberpunk War Room dashboard built with pure ASGI FastAPI.

The project fulfills all requirements of **Project 09 (API Under Attack — Stop the Request Storm)** from the *Cyber Security and Digital Resilience Student Instructional Guide*:
- **Core Security Themes:** Abuse resistance, rate limiting, observability, and graceful degradation.
- **Core Cloud Services (with Local Adapters):** Google Cloud Run, Google Cloud Firestore, Google Cloud Logging, Google Cloud Monitoring.
- **Sandbox Isolation:** Multi-tenant session sandboxing allowing independent rate limiting, metrics, attack simulations, and configuration tuning.

---

## 📁 Standardized Project Structure

The repository is organized according to Section 5 of the *Infrastructure Setup Guide*:

```text
stop-the-request-storm/
├── README.md                            # Project guide, quickstart & submission checklist
├── API_DOCUMENTATION.md                 # Complete API endpoint reference & schemas
├── Dockerfile                           # Google Cloud Run container specification
├── Procfile                             # Process file for persistent cloud hosts
├── requirements.txt                     # Application runtime dependencies
├── main.py                              # ASGI entrypoint, health, static & control routes
├── config.py                            # DefenseConfig, key registry & endpoint cost map
├── upstream.py                          # Mock campus API endpoints & capacity semaphore
├── session_manager.py                   # Multi-tenant session sandbox manager
├── metrics.py                           # Telemetry ring buffers, latency percentiles & masking
├── cloud/                               # Cloud service adapters (Environment Caveat compliance)
│   ├── cloud_logging.py                 # Structured Google Cloud Logging & audit event emitter
│   ├── cloud_monitoring.py              # Cloud Monitoring custom metrics adapter
│   └── firestore_store.py               # Firestore distributed state store adapter
├── limiters/                            # Core rate limiting algorithm implementations
│   ├── base.py                          # RateLimiterStrategy interface & Decision model
│   ├── token_bucket.py                  # Token Bucket continuous refill strategy
│   ├── sliding_window.py                # Sliding Window Counter sub-window strategy
│   └── leaky_bucket.py                  # Leaky Bucket queue shaper strategy
├── middleware/                          # Pure ASGI security middleware
│   └── shield_middleware.py             # ShieldMiddleware (metering, gating, headers & logs)
├── storage/                             # Storage state backends
│   ├── base.py                          # BaseStorage abstract interface
│   ├── memory_store.py                  # In-memory thread-safe state store (Default)
│   └── redis_store.py                   # Optional Redis plugin store
├── simulator/                           # Loopback synthetic attack traffic generator
│   └── storm_generator.py               # Normal, DDoS, Exhaustion, and Botnet patterns
├── docs/                                # Architecture, threat model, access & test docs
│   ├── architecture.md                  # System architecture, data flows & threat model
│   ├── cloud_services.md                # Cloud services, verified ops & environment adapters
│   ├── access_and_secrets.md            # Secret management, least privilege & data scrubbing
│   ├── findings_register.md             # Findings register (FR-01 to FR-06)
│   ├── test_matrix.md                   # Completed T01–T08 test matrix
│   ├── first_run_verification.md        # Pre-project setup checklist verification
│   ├── changelog.md                     # Team changelog & work history
│   └── demo_plan.md                     # 7–10 minute demonstration agenda & script
├── evidence/                            # Traceable before/after logs & test outputs
│   ├── baseline_assessment.log          # Baseline unshielded denial-of-service evidence
│   ├── T01_requests_below_threshold.log # Test T01 allowed requests evidence
│   ├── T02_requests_above_threshold_rejected.log # Test T02 throttled 429 evidence
│   ├── T03_limiter_window_reset.log     # Test T03 token refill evidence
│   ├── T04_valid_requests_resume.log    # Test T04 resumed request evidence
│   ├── T05_structured_security_events.log # Test T05 Cloud Logging sanitized evidence
│   ├── T06_controlled_error_handling.log # Test T06 safe 500 error & correlation log
│   ├── T07_secret_and_pii_audit.log     # Test T07 sensitive data audit scan
│   └── T08_reproducible_test_run.log    # Test T08 full test suite execution evidence
├── report/                              # Security assessment report & presentation
│   ├── SECURITY_ASSESSMENT_REPORT.md    # Formal 5-page Security Assessment Report
│   └── presentation.md                  # Team presentation slide outline
├── static/                              # Dark cyberpunk real-time War Room UI
│   └── index.html                       # Real-time SVG telemetry graphs & request log
└── tests/                               # Automated test suites
    ├── test_spec_matrix.py              # Required test matrix suite (T01 - T08)
    ├── test_middleware.py               # Rate limit headers & graceful degradation tests
    ├── test_token_bucket.py             # Token bucket unit tests
    ├── test_sliding_window.py           # Sliding window unit tests
    ├── test_leaky_bucket.py             # Leaky bucket queue shaper tests
    ├── test_memory_store.py             # In-memory storage cap & LRU sweep tests
    ├── test_concurrency.py              # 500-request race condition test
    ├── test_sessions.py                 # Multi-user session isolation tests
    ├── test_status_and_logs.py          # Request log & identity masking tests
    └── test_redis_store.py              # Redis plugin store tests
```

---

## 👥 Team Roles & Responsibilities

| Role | Responsibility | Primary Artifact |
|---|---|---|
| **1. Security Architect** | Map assets, data flows, threats and release criteria | [docs/architecture.md](file:///a:/Cybersec/docs/architecture.md), [report/SECURITY_ASSESSMENT_REPORT.md](file:///a:/Cybersec/report/SECURITY_ASSESSMENT_REPORT.md) |
| **2. Cloud Security Engineer** | Verify service setup, identities and supported operations | [docs/cloud_services.md](file:///a:/Cybersec/docs/cloud_services.md), [cloud/](file:///a:/Cybersec/cloud) |
| **3. Application Security Engineer** | Implement defensive workflow and remediation | [middleware/shield_middleware.py](file:///a:/Cybersec/middleware/shield_middleware.py), [limiters/](file:///a:/Cybersec/limiters) |
| **4. Identity & Data Security Engineer** | Review access, data minimisation and secret/key handling | [docs/access_and_secrets.md](file:///a:/Cybersec/docs/access_and_secrets.md), [metrics.py](file:///a:/Cybersec/metrics.py) |
| **5. Detection, Testing & Evidence Engineer** | Design tests, inspect logs and assemble evidence | [tests/test_spec_matrix.py](file:///a:/Cybersec/tests/test_spec_matrix.py), [evidence/](file:///a:/Cybersec/evidence) |

---

## ⚡ Core Security Controls Implemented

1. **Multi-Algorithm Rate Limiting:**
   - **Token Bucket:** Classic burst-tolerant continuous refill.
   - **Sliding Window Counter:** Sub-window weighted approximation preventing boundary burst exploitation.
   - **Leaky Bucket / Queue Shaper:** Strict smooth outflow spacing with bounded async delay scheduling.
2. **Tiered Identity & Cardinality Gating:** Built-in demo keys (`free-demo-key` 1x, `pro-demo-key` 5x, `ent-demo-key` 20x). Unknown or forged keys map to the caller's IP bucket, preventing cardinality memory depletion attacks.
3. **Adaptive Storm Defense:** Automatically detects high-RPS waves (>100 RPS) and distinct IP floods, tightening anonymous quotas by 50% while prioritizing paying tiers.
4. **Graceful Degradation:** Stale-While-Revalidate (SWR) cached fallback on cacheable GET reads (`GET /api/data`) during traffic spikes, returning `200 Cached-Fallback` instead of drops.
5. **Structured Audit Logging & Correlation Tracking:** Emits Google Cloud Logging JSON entries containing timestamps, severities, and correlation IDs (`X-Correlation-Id`).
6. **Data Minimization:** IPv4 addresses masked to `*.*`, raw API keys masked to `API_KEY [TIER]`, and recursive payload scrubbers redacting sensitive fields.
7. **Safe Controlled Error Handling:** Safe HTTP 500 error responses preventing internal stack traces or connection strings from leaking to clients.

---

## 🧪 Verification & Required Test Matrix (T01 – T08)

All 8 tests specified in Section 8 of the Project Guide are implemented and automated in [tests/test_spec_matrix.py](file:///a:/Cybersec/tests/test_spec_matrix.py):

| ID | Test | Expected Result | Status | Traceable Evidence |
|---|---|---|---|---|
| **T01** | Requests below threshold succeed. | Documented expected behaviour; unsafe/unauthorised action prevented. | **PASS** | [T01_requests_below_threshold.log](file:///a:/Cybersec/evidence/T01_requests_below_threshold.log) |
| **T02** | Requests above threshold are rejected consistently. | Documented expected behaviour; unsafe/unauthorised action prevented. | **PASS** | [T02_requests_above_threshold_rejected.log](file:///a:/Cybersec/evidence/T02_requests_above_threshold_rejected.log) |
| **T03** | Limiter resets according to its documented window. | Documented expected behaviour; unsafe/unauthorised action prevented. | **PASS** | [T03_limiter_window_reset.log](file:///a:/Cybersec/evidence/T03_limiter_window_reset.log) |
| **T04** | Valid requests resume after the limit window. | Documented expected behaviour; unsafe/unauthorised action prevented. | **PASS** | [T04_valid_requests_resume.log](file:///a:/Cybersec/evidence/T04_valid_requests_resume.log) |
| **T05** | Logs/metrics show decisions without sensitive data. | Documented expected behaviour; unsafe/unauthorised action prevented. | **PASS** | [T05_structured_security_events.log](file:///a:/Cybersec/evidence/T05_structured_security_events.log) |
| **T06** | Trigger a controlled unexpected error. | Safe response; useful event recorded. | **PASS** | [T06_controlled_error_handling.log](file:///a:/Cybersec/evidence/T06_controlled_error_handling.log) |
| **T07** | Inspect source, output and logs for sensitive data. | No secret or unnecessary sensitive data exposed. | **PASS** | [T07_secret_and_pii_audit.log](file:///a:/Cybersec/evidence/T07_secret_and_pii_audit.log) |
| **T08** | Repeat the complete test set. | Results are reproducible and limitations documented. | **PASS** | [T08_reproducible_test_run.log](file:///a:/Cybersec/evidence/T08_reproducible_test_run.log) |

### Run the Test Suites

Run the dedicated Project 09 Test Matrix:
```bash
python -m pytest tests/test_spec_matrix.py -v
```

Run the complete test suite (30 automated tests):
```bash
python -m pytest -v
```

---

## 🚀 Quickstart (Local Run)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Boot Server
```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1
```

### 3. Open War Room Dashboard
Navigate to `http://127.0.0.1:8000/` in your browser.

---

## 📦 Submission Checklist (Section 14)

- [x] Application source code and README with run instructions.
- [x] Architecture/data-flow diagram and threat assumptions ([docs/architecture.md](file:///a:/Cybersec/docs/architecture.md)).
- [x] Findings register with severity and remediation ([docs/findings_register.md](file:///a:/Cybersec/docs/findings_register.md)).
- [x] Completed test matrix with before-and-after evidence ([docs/test_matrix.md](file:///a:/Cybersec/docs/test_matrix.md) & [evidence/](file:///a:/Cybersec/evidence)).
- [x] Redacted logs, alerts or integrity evidence, labelled accurately ([evidence/](file:///a:/Cybersec/evidence)).
- [x] Explanation of access, secret/key handling and verified service operations ([docs/access_and_secrets.md](file:///a:/Cybersec/docs/access_and_secrets.md) & [docs/cloud_services.md](file:///a:/Cybersec/docs/cloud_services.md)).
- [x] Security Assessment Report with environment limitations stated clearly ([report/SECURITY_ASSESSMENT_REPORT.md](file:///a:/Cybersec/report/SECURITY_ASSESSMENT_REPORT.md)).
- [x] 7–10 minute demo plan and evidence-based release recommendation ([docs/demo_plan.md](file:///a:/Cybersec/docs/demo_plan.md)).
