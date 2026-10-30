# Project Change Log

**Project:** Project 09 · API Under Attack — Stop the Request Storm  
**Program:** BMSCE × MindMatrix Skill Lab Initiative  

---

| Date | Team Member / Role | Change Made | Test Performed | Result |
|---|---|---|---|---|
| **2026-10-28** | Security Architect | Defined threat boundaries, student assets, and request storm attack vector. | Threat model review | Architecture accepted |
| **2026-10-29** | Cloud Security Engineer | Configured Cloud Run container spec (`Dockerfile`) and verified environment variables (`PORT`, `STORE_BACKEND`). | Build & boot smoke test | Container operational |
| **2026-10-29** | Application Security Engineer | Built baseline API and reproduced unshielded denial of service under 20 rapid GET requests. | Baseline flood assessment | Starvation observed (`evidence/baseline_assessment.log`) |
| **2026-10-29** | Application Security Engineer | Implemented pure ASGI `ShieldMiddleware` with Token Bucket, Sliding Window, and Leaky Bucket algorithms. | Unit tests for algorithms | All 3 algorithms passing |
| **2026-10-30** | Identity & Data Security Engineer | Implemented API key registry tiering (`DEMO_KEY_REGISTRY`) and IP fallback to prevent cardinality attacks. | `test_unknown_api_key_falls_back_to_ip_bucket` | Key cardinality capped |
| **2026-10-30** | Identity & Data Security Engineer | Added identity masking (`mask_identity`), IPv4 octet scrubbers (`*.*`), and log sanitization. | `test_mask_identity` | Zero plaintext PII or keys leaked |
| **2026-10-30** | Detection, Testing & Evidence Engineer | Implemented Google Cloud Logging structured adapter and Cloud Monitoring metric descriptors. | `test_t05_logs_metrics_show_decisions_without_sensitive_data` | Structured audit entries verified |
| **2026-10-30** | Detection, Testing & Evidence Engineer | Implemented controlled unexpected error endpoint (`GET /api/controlled-error`) and safe exception wrapper. | `test_t06_trigger_controlled_unexpected_error` | Safe 500 response, no stack traces leaked |
| **2026-10-30** | Full Team | Implemented formal Test Matrix suite (`tests/test_spec_matrix.py`) covering T01 through T08. | `pytest tests/test_spec_matrix.py` | 8/8 tests passed (100%) |
| **2026-10-30** | Full Team | Generated repeatable evidence files in `evidence/` and authored 5-page Security Assessment Report. | Audit & documentation verification | Complete submission package ready |
