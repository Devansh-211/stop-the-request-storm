# Completed Test Matrix (T01 - T08)

**Project:** Project 09 · API Under Attack — Stop the Request Storm  
**Program:** BMSCE × MindMatrix Skill Lab Initiative  

> **PASS CRITERION (Instructional Guide Page 61):**  
> *"A test passes only when the team shows the observed result and explains why it meets the expected behaviour. A code change alone is not proof of remediation."*

---

## Test Execution Results

| ID | Test Case | Expected Result After Fix | Observed Result | Status | Traceable Evidence File |
|---|---|---|---|---|---|
| **T01** | Requests below threshold succeed. | Valid requests below capacity succeed (HTTP 200), tokens decrement predictably, and rate limit headers + correlation ID are present. | 5 consecutive requests to `/api/ping` returned HTTP 200, decrementing `x-ratelimit-remaining` from 9 down to 5. `x-correlation-id` and `x-session-id` injected. | **PASS** | [T01_requests_below_threshold.log](file:///a:/Cybersec/evidence/T01_requests_below_threshold.log) |
| **T02** | Requests above threshold are rejected consistently. | Once quota is exhausted, subsequent non-cacheable / write requests are rejected consistently with HTTP 429 and integer `Retry-After`. | Calling `/api/heavy-compute` (cost 5) twice consumed 10 tokens. Third and fourth requests were rejected with HTTP 429, `retry-after: 3`, and remaining 0. | **PASS** | [T02_requests_above_threshold_rejected.log](file:///a:/Cybersec/evidence/T02_requests_above_threshold_rejected.log) |
| **T03** | Limiter resets according to its documented window. | Bucket refills continuously at `base_refill_rate` tokens per second or resets upon sliding window roll-over. | After quota exhaustion, a 1.05s wait with refill rate 4.0 tokens/s replenished available quota to 3 tokens, restoring admission. | **PASS** | [T03_limiter_window_reset.log](file:///a:/Cybersec/evidence/T03_limiter_window_reset.log) |
| **T04** | Valid requests resume after the limit window. | Legitimate client requests resume normal operation (HTTP 200) once cooldown window expires. | Following cooldown period, calling `/api/ping` succeeded immediately with HTTP 200 and standard payload. | **PASS** | [T04_valid_requests_resume.log](file:///a:/Cybersec/evidence/T04_valid_requests_resume.log) |
| **T05** | Logs/metrics show decisions without sensitive data. | Telemetry records timestamps, outcome, and correlation IDs without raw API keys, passwords, or unmasked IPs. | Structured audit logs verified: IPs masked to `198.51.*.*`, API keys labeled `API_KEY [PRO]`, passwords replaced with `[REDACTED]`. | **PASS** | [T05_structured_security_events.log](file:///a:/Cybersec/evidence/T05_structured_security_events.log) |
| **T06** | Trigger a controlled unexpected error. | Controlled error trigger returns safe HTTP 500 response without stack traces or DB internals; structured error event logged. | `GET /api/controlled-error` returned clean JSON with `correlation_id: corr-audit-t06-demo`. Structured error event was logged with severity ERROR. | **PASS** | [T06_controlled_error_handling.log](file:///a:/Cybersec/evidence/T06_controlled_error_handling.log) |
| **T07** | Inspect source, output and logs for sensitive data. | No private keys, cloud tokens, production passwords, or real personal student data in code, logs, or responses. | Regex scanner inspected 25+ files. Zero RSA keys, AWS/GCP real tokens, or personal identifiers found. All demo data strictly synthetic. | **PASS** | [T07_secret_and_pii_audit.log](file:///a:/Cybersec/evidence/T07_secret_and_pii_audit.log) |
| **T08** | Repeat the complete test set. | Complete test matrix executes deterministically and repeatedly with 100% reproducible results. | Full pytest suite ran: 30 passed, 1 skipped (offline Redis). Verified deterministic test repeatability across all test modules. | **PASS** | [T08_reproducible_test_run.log](file:///a:/Cybersec/evidence/T08_reproducible_test_run.log) |

---

## Reproducibility Command

To independently reproduce the entire test matrix:
```bash
python -m pytest tests/test_spec_matrix.py -v
```
