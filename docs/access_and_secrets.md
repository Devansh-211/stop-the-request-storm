# Access Control, Secrets & Data Minimization

**Project:** Project 09 · API Under Attack — Stop the Request Storm  
**Program:** BMSCE × MindMatrix Skill Lab Initiative  

---

## 1. Secret Management Policy & Verification

In accordance with Section 8 (*Security and responsible-use rules*) of the MindMatrix Instructional Guide:
- **Zero Real Credentials:** No production API keys, database connection strings, passwords, or cloud private keys are committed into source code, Git history, screenshots, or reports.
- **Demo Key Registry:** A synthetic mock key registry (`DEMO_KEY_REGISTRY`) is defined strictly for coursework demonstration:
  - `free-demo-key` -> Free Tier (1.0x baseline capacity)
  - `pro-demo-key` -> Pro Tier (5.0x baseline capacity)
  - `ent-demo-key` -> Enterprise Tier (20.0x baseline capacity)
- **Runtime Secret Retrieval:** Any administrative control operations requiring elevated privilege (such as `GET /control/admin/sessions`) read credentials dynamically from the environment (`ADMIN_TOKEN`) rather than hardcoded variables.
- **Automated Verification:** Test `T07` runs automated regex scanners across all repository files to guarantee no private keys, AWS tokens, or cloud service credentials exist.

---

## 2. Least Privilege & Role-Based Access Control (RBAC)

| Role / Identity | Admission Quota | Cost Multiplier | Storm Mode Treatment | Privileged Control Access |
|---|---|---|---|---|
| **Anonymous IP** | Base (10 tokens) | 1.0x | Tightened by 50% | Denied |
| **FREE Tier Key** | Base (10 tokens) | 1.0x | Tightened by 50% | Denied |
| **PRO Tier Key** | 50 tokens | 5.0x | Priority Admitted | Denied |
| **ENTERPRISE Tier Key** | 200 tokens | 20.0x | Guaranteed Upstream Bypass | Denied |
| **Administrator** | N/A (Exempt) | Exempt | System Monitor | Granted via `ADMIN_TOKEN` or local loopback |

### Cardinality Flood Defense (Least Privilege Storage Policy)
Attackers frequently forge random, high-cardinality API keys (e.g. `X-API-Key: random-attacker-12345`) to exhaust server memory by creating millions of separate rate limit buckets.  
**Control:** The gateway evaluates API keys against the verified registry. Unregistered or malformed keys are denied separate bucket creation and are mapped strictly to the caller's shared IP bucket (`ip:<client_ip>`), neutralizing memory depletion attacks.

---

## 3. Data Minimization & Privacy Scrubbing

To prevent accidental data leakage in shared labs, reports, or dashboards:

1. **IPv4 Address Masking:**
   - Raw IP addresses are scrubbed so that only the first two octets remain visible (e.g., `198.51.*.*`, `203.0.*.*`).
   - The remaining host octets are replaced with asterisks before telemetry storage or display.

2. **API Key Redaction:**
   - Raw API key strings are never stored in the live request log or structured audit logs.
   - Keys are mapped immediately to their tier descriptor (e.g., `API_KEY [PRO]` or `API_KEY [ENTERPRISE]`).

3. **Log Sanitization:**
   - `cloud/cloud_logging.py` executes recursive payload sanitization, automatically replacing sensitive fields (`password`, `token`, `secret`, `authorization`, `cookie`) with `[REDACTED]`.
   - Error messages return sanitized responses without stack traces, internal file paths, or SQL queries.
