# First-Run Verification Checklist

**Project:** Project 09 · API Under Attack — Stop the Request Storm  
**Program:** MindMatrix <> BMSCE Skill Lab Initiative  

---

## 1. Environment & Pre-Run Checks (Section 6 of Setup Guide)

| Check Item | Command / Action | Expected Result | Observed Result | Status |
|---|---|---|---|---|
| **Web Browser** | Open Dashboard URL (`http://127.0.0.1:8000/`) | Cyberpunk War Room Dashboard loads with real-time SVG charts and session badge. | Dashboard rendered cleanly; session badge `SANDBOX: [id]` displayed. | **Pass** |
| **Git** | `git --version` | Version number appears | `git version 2.44.0.windows.1` | **Pass** |
| **VS Code** | Launch VS Code and open project folder | Workspace opens without errors | Clean workspace loaded | **Pass** |
| **Python** | `python --version` | Python 3.10+ installed and on PATH | `Python 3.14.2` | **Pass** |
| **Node.js** | `node --version` | Optional tool check | N/A (Project is pure Python ASGI) | **N/A** |
| **Docker** | `docker --version` | Optional container builder check | Verified Dockerfile available | **Pass** |
| **Lab Permissions** | Open local/cloud test sandbox | Required services accessible | Local ASGI server and Cloud Run container target ready | **Pass** |
| **Evidence Folder** | Create and save test files in `evidence/` | File saves and team can access it | 9 traceable `.log` evidence files recorded in `evidence/` | **Pass** |

---

## 2. Safety & Responsible-Use Rule Attestation

- [x] All tests run exclusively against localhost / local ASGI test client and designated sandbox environments.
- [x] No scanning, brute-forcing, or stress-testing against college networks, external IPs, or production systems.
- [x] All test data uses synthetic RFC 5737 testnet IP addresses (`198.51.100.*`, `203.0.113.*`) and synthetic mock keys.
- [x] Zero plain credentials committed in code, git commits, screenshots, or reports.
