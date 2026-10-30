# Final Demonstration Plan (7–10 Minutes)

**Project:** Project 09 · API Under Attack — Stop the Request Storm  
**Program:** BMSCE × MindMatrix Skill Lab Initiative  

This demonstration script follows the exact timing and agenda defined in Section 10 of the Student Instructional Guide.

---

## Demonstration Timeline & Script

| Timing | Segment | Speaker / Lead Role | Action & Talking Points | Visual / Evidence Displayed |
|---|---|---|---|---|
| **0:00 – 1:00 (1 min)** | Scenario, Protected Assets & Key Risks | **Security Architect** | - Introduce CampusShield: API gateway protecting campus microservices.<br>- Assets: Health probe (`/api/ping`), analytics query (`/api/data`), compute service (`/api/heavy-compute`).<br>- Threat: Volumetric DDoS request storm causing upstream starvation and outage. | Architecture Diagram ([docs/architecture.md](file:///a:/Cybersec/docs/architecture.md)) |
| **1:00 – 3:00 (2 min)** | Reproduce Baseline Weakness Safely | **Application Security Engineer** | - Open War Room Dashboard in Browser A.<br>- Turn Master Shield switch **OFF (DANGER)**.<br>- Trigger 150 RPS DDoS flood in Attack Simulator.<br>- Explain impact: All requests flood backend unchecked, latency spikes, upstream semaphore saturates, legitimate users starved. | Live Dashboard showing unshielded RPS spike and [baseline_assessment.log](file:///a:/Cybersec/evidence/baseline_assessment.log) |
| **3:00 – 5:00 (2 min)** | Engage Control / Fix & Repeat Test | **Application Security Engineer** | - Flip Master Shield switch **ON (ARMED)**.<br>- Re-run the attack storm with Token Bucket / Sliding Window.<br>- Show defensive response: Influx is instantly capped; non-cacheable abuse blocked with HTTP 429 and `Retry-After`; read route degrades gracefully to `200 Cached-Fallback`. | Real-time SVG chart showing green Accepted line capped, yellow Degraded line active, red Blocked line mitigating flood. |
| **5:00 – 6:30 (1.5 min)** | Service, Identity, Key & Secret Workflow | **Cloud & Identity Engineers** | - Explain zero hardcoded secrets and environment variable configuration.<br>- Show Tiered API key registry (`DEMO_KEY_REGISTRY`): Free (1x), Pro (5x), Enterprise (20x).<br>- Demonstrate cardinality flood protection: random forged keys map to caller IP bucket.<br>- Distinguish verified Cloud Run deployment from local emulator adapters (Environment Caveat). | [docs/cloud_services.md](file:///a:/Cybersec/docs/cloud_services.md) & [docs/access_and_secrets.md](file:///a:/Cybersec/docs/access_and_secrets.md) |
| **6:30 – 7:30 (1 min)** | Redacted Logs, Alerts & Integrity Evidence | **Detection & Evidence Engineer** | - Inspect live Request Log table and Google Cloud Logging structured format.<br>- Highlight privacy controls: IP masked (`198.51.*.*`), keys masked (`API_KEY [PRO]`), correlation IDs tracked.<br>- Demonstrate controlled error handling (T06): trigger error, show safe 500 JSON and structured audit event. | [evidence/T05_structured_security_events.log](file:///a:/Cybersec/evidence/T05_structured_security_events.log) & [evidence/T06_controlled_error_handling.log](file:///a:/Cybersec/evidence/T06_controlled_error_handling.log) |
| **7:30 – 9:00 (1.5 min)** | Test Results, Limitations & Release Decision | **Security Architect** | - Review Completed Test Matrix: 8/8 tests passed (100% pass rate).<br>- Discuss documented limitations (single-worker in-memory state vs multi-instance Firestore).<br>- State final evidence-based release decision: **Conditional Release for Production Deployment**. | Completed Test Matrix ([docs/test_matrix.md](file:///a:/Cybersec/docs/test_matrix.md)) & [report/SECURITY_ASSESSMENT_REPORT.md](file:///a:/Cybersec/report/SECURITY_ASSESSMENT_REPORT.md) |

---

## Backup / Troubleshooting Checklist

If any live network failure occurs during the demonstration:
1. Re-run local test matrix: `python -m pytest tests/test_spec_matrix.py -v`.
2. Open pre-generated evidence artifacts in `evidence/` to show forensic log excerpts.
3. Switch dashboard to mock polling mode if WebSocket is interrupted.
