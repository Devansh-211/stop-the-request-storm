# CampusShield — Stop the Request Storm
## Defensive API Protection & Real-Time Cyber War Room
**Cybersecurity Project 09 · BMSCE × MindMatrix Skill Lab Initiative**  
**Team 9 Final Presentation**

---

### Slide 1: Title & Challenge Overview
- **Project Challenge:** Simulate a burst of API requests, demonstrate unmitigated denial of service, and implement application-level rate limiting, request rejection, graceful degradation, and security logging.
- **Team Structure:**
  - Security Architect
  - Cloud Security Engineer
  - Application Security Engineer
  - Identity & Data Security Engineer
  - Detection, Testing & Evidence Engineer

---

### Slide 2: The Problem — Unchecked Request Storms
- Modern campus portals and student APIs are frequent targets of traffic spikes, bot scraping, and DDoS storms.
- **Baseline Vulnerability (FR-01):** Unshielded APIs accept all incoming requests, saturating server concurrency semaphores and causing legitimate requests to time out.
- **Cardinality Flood Threat (FR-02):** Attackers sending random API keys can exhaust server RAM by spawning millions of state buckets.

---

### Slide 3: Proposed Architecture & Trust Boundaries
- **Edge Security Perimeter:** Pure ASGI `ShieldMiddleware` evaluating every request with zero blocking delay.
- **Defense Controls:**
  - Token Bucket: Burst-tolerant continuous refill.
  - Sliding Window Counter: Sub-window weighting to eliminate boundary burst double-spending.
  - Leaky Bucket / Queue Shaper: Deterministic inter-arrival pacing.
  - Adaptive Storm Gate: Automatically detects volumetric spikes (>100 RPS) and tightens unauthenticated quotas by 50%.
  - Stale-While-Revalidate (SWR): Degrades read routes (`GET /api/data`) to cached snapshots instead of 429 drops.

---

### Slide 4: Cloud Services & Environment Integration
- **Google Cloud Run:** Single-worker containerized deployment (`Dockerfile`).
- **Google Cloud Firestore:** Distributed bucket state storage with transparent local memory fallback adapter.
- **Google Cloud Logging:** Structured JSON audit logging with correlation ID propagation.
- **Google Cloud Monitoring:** Custom metrics (`request_count`, `blocked_count`, `degraded_count`, `storm_mode_active`).
- **Zero Real Secrets:** Strict least-privilege key registry (`free`, `pro`, `enterprise`), IP masking (`*.*`), and zero committed secrets.

---

### Slide 5: Verification & Test Matrix (T01 – T08)
- **T01 (Below Threshold):** PASS — 100% accepted with rate limit headers.
- **T02 (Above Threshold):** PASS — 429 Too Many Requests + integer `Retry-After`.
- **T03 (Window Reset):** PASS — Replenishes tokens at configured refill rate.
- **T04 (Requests Resume):** PASS — Normal operations resume immediately after cooldown.
- **T05 (Sanitized Logs):** PASS — Masked IPs (`198.51.*.*`), masked keys (`API_KEY [PRO]`), correlation IDs tracked.
- **T06 (Controlled Error):** PASS — Safe HTTP 500 response without stack traces; structured error event logged.
- **T07 (Sensitive Data Audit):** PASS — Zero private keys, AWS/GCP secrets, or personal data.
- **T08 (Reproducibility):** PASS — 30/30 automated pytest tests passing deterministically.

---

### Slide 6: Live War Room Demonstration
- Live demonstration of two-browser session isolation:
  - Browser A under 150 RPS DDoS flood.
  - Browser B operating with pristine latency and zero dropped requests.
- Master Shield toggle demonstrating before/after remediation live.
- Real-time SVG telemetry charts and live request log drawer.

---

### Slide 7: Conclusion & Release Recommendation
- **Release Decision:** **CONDITIONAL RELEASE**.
- All security requirements, evidence artifacts, and test matrices verified.
- Production deployment recommended with distributed Firestore or Redis caching.
