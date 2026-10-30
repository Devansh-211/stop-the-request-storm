# Security Findings Register

**Project:** Project 09 · API Under Attack — Stop the Request Storm  
**Program:** BMSCE × MindMatrix Skill Lab Initiative  

---

### Severity Classification Reference (Per Section 9 of Project Guide)
- **High:** Could expose sensitive data, allow unintended execution, or permit unauthorised changes or complete service denial in this scenario.
- **Medium:** Materially weakens a control or exposes unnecessary information, with limited demonstrated impact.
- **Low:** Limited weakness or improvement opportunity with small demonstrated impact.
- **Informational:** Observation or hardening recommendation without a demonstrated vulnerability.

---

## Findings Table

| ID | Finding Title | Severity | Impact | Remediation Applied | Retest Result | Evidence Reference |
|---|---|---|---|---|---|---|
| **FR-01** | Unchecked Volumetric Request Storm Leading to Upstream Starvation | **High** | Unthrottled traffic saturated backend mock server, driving latency from 20ms to >2000ms and dropping legitimate requests. | Implemented multi-algorithm rate limiter (`ShieldMiddleware`) with Token Bucket, Sliding Window, and Leaky Bucket strategies. | **Resolved** | [baseline_assessment.log](file:///a:/Cybersec/evidence/baseline_assessment.log)<br>[T02_requests_above_threshold_rejected.log](file:///a:/Cybersec/evidence/T02_requests_above_threshold_rejected.log) |
| **FR-02** | Cardinality Abuse via Random API Key Floods | **High** | Attackers sending random `X-API-Key` headers could spawn millions of in-memory rate limiter buckets, inducing Out-Of-Memory (OOM) crash. | Restricted bucket allocation to validated key registry (`DEMO_KEY_REGISTRY`). Unknown keys fall back strictly to the client IP bucket. | **Resolved** | [test_middleware.py](file:///a:/Cybersec/tests/test_middleware.py#L54-L65) |
| **FR-03** | Boundary Double-Burst Vulnerability in Fixed Window Counters | **Medium** | Fixed window counters permit 2x traffic spikes at window boundaries (e.g. 10 requests at t=0.9s and 10 requests at t=1.1s). | Added Sliding Window Counter with sub-window weighted approximation, preventing boundary burst exploitation. | **Resolved** | [test_sliding_window.py](file:///a:/Cybersec/tests/test_sliding_window.py#L35-L65) |
| **FR-04** | Complete Drop of Read Traffic During Traffic Surges | **Medium** | Legitimate users querying read-only analytics (`GET /api/data`) were dropped with 429 errors during concurrent floods. | Implemented Stale-While-Revalidate (SWR) Graceful Degradation cache, serving cached snapshots (`200 Cached-Fallback`) when throttled. | **Resolved** | [test_middleware.py](file:///a:/Cybersec/tests/test_middleware.py#L68-L89) |
| **FR-05** | Raw Credential & Full IP Exposure in Logs and Dashboards | **Medium** | Logging raw client IPs and API tokens exposed sensitive telemetry in shared lab screens and logs. | Added `mask_identity()` and `sanitize_payload()` scrubbers in telemetry and structured security logger, masking IPs (`*.*`) and tokens (`API_KEY [TIER]`). | **Resolved** | [T05_structured_security_events.log](file:///a:/Cybersec/evidence/T05_structured_security_events.log)<br>[T07_secret_and_pii_audit.log](file:///a:/Cybersec/evidence/T07_secret_and_pii_audit.log) |
| **FR-06** | Uncontrolled Internal Exceptions Leaking Server Internals | **Low** | Unhandled server errors could expose stack traces, software versions, and internal file paths to callers. | Implemented safe exception handler in ASGI middleware, returning sanitized HTTP 500 JSON with correlation ID and logging structured audit events. | **Resolved** | [T06_controlled_error_handling.log](file:///a:/Cybersec/evidence/T06_controlled_error_handling.log) |

---

## Retest & Verification Summary

All 6 identified findings (FR-01 through FR-06) have been remediated, verified with automated unit and integration tests, and validated with repeatable evidence captures stored in the [evidence/](file:///a:/Cybersec/evidence) directory.
