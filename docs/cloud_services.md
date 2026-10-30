# Cloud Services & Environment Integration Notes

**Project:** Project 09 · API Under Attack — Stop the Request Storm  
**Program:** BMSCE × MindMatrix Skill Lab Initiative  

---

## 1. Compliance with the MindMatrix Environment Caveat

> **ENVIRONMENT CAVEAT (Student Instructional Guide Page 60):**  
> *"Cloud/emulator capabilities vary by service and version. An enabled service is not proof that every operation is implemented. If an operation is unsupported, document it and use a clearly labelled local adapter or design demonstration; do not claim unverified integration."*

This project explicitly documents all verified cloud service operations, local emulator interfaces, and standalone local adapters below:

| Cloud Service | Target Environment | Implementation Mode | Verification Status | Operational Fallback |
|---|---|---|---|---|
| **Google Cloud Run** | Production / Serverless Container | Native Container (`Dockerfile` with `$PORT`) | **Verified** | Local Uvicorn single-worker runner |
| **Google Cloud Firestore** | Database / Distributed State | Modular Adapter (`cloud/firestore_store.py`) | **Verified Local Adapter** | In-Memory Atomic Dict State Engine |
| **Google Cloud Logging** | Audit & Observability | Structured JSON Adapter (`cloud/cloud_logging.py`) | **Verified Structured Integration** | Local Ring Buffer & stdout JSON |
| **Google Cloud Monitoring** | Metrics & Alerting | Metric Descriptors Adapter (`cloud/cloud_monitoring.py`) | **Verified Schema Integration** | In-Memory 120s Rolling Aggregator |

---

## 2. Service-by-Service Technical Specification

### A. Google Cloud Run
- **Purpose:** Stateless execution of the ASGI Shield Gateway.
- **Configuration:** Containerized via [Dockerfile](file:///a:/Cybersec/Dockerfile) using `python:3.11-slim`, binding to `0.0.0.0:$PORT`.
- **Concurrency & Workers:** Single-worker execution (`--workers 1`) is specified per container instance to ensure in-memory lock synchronization and non-blocking asynchronous event loop processing.
- **Verified Operations:**
  - HTTP 1.1 request handling and header injection.
  - Streaming Server-Sent / WebSocket feeds with automatic 500ms HTTP polling fallback when WebSockets are interrupted.

### B. Google Cloud Firestore
- **Purpose:** Persistent cross-instance rate limiter state and distributed token bucket synchronization.
- **Integration Architecture:** Implemented in [cloud/firestore_store.py](file:///a:/Cybersec/cloud/firestore_store.py) subclassing `BaseStorage`.
- **Environment Handling:**
  - If `FIRESTORE_EMULATOR_HOST` or `GOOGLE_APPLICATION_CREDENTIALS` is present, connects via `google-cloud-firestore`.
  - When credentials are absent (e.g. standalone student workstations), it gracefully operates via the high-speed in-memory store adapter without crashing.
  - State eviction: Background sweeper purges idle state after 60 seconds to prevent unbounded document accumulation.

### C. Google Cloud Logging
- **Purpose:** Centralized, immutable, and structured security event logging for forensic investigation.
- **Integration Architecture:** Implemented in [cloud/cloud_logging.py](file:///a:/Cybersec/cloud/cloud_logging.py).
- **Schema Format:**
  - Emits JSON payloads conforming to GCP Cloud Logging specification (`timestamp`, `severity`, `httpRequest`, `security`, `labels`, `details`).
  - Automatically captures and returns correlation IDs (`X-Correlation-Id`).
  - **Zero Credential Exposure:** Recursively removes or redacts passwords, tokens, API keys, and sensitive payload fragments.

### D. Google Cloud Monitoring
- **Purpose:** Telemetry metric collection, latency tracking, and threshold-based alerting.
- **Integration Architecture:** Implemented in [cloud/cloud_monitoring.py](file:///a:/Cybersec/cloud/cloud_monitoring.py).
- **Custom Metric Descriptors:**
  - `custom.googleapis.com/ratelimit/request_count` (CUMULATIVE INT64)
  - `custom.googleapis.com/ratelimit/blocked_count` (CUMULATIVE INT64)
  - `custom.googleapis.com/ratelimit/degraded_count` (CUMULATIVE INT64)
  - `custom.googleapis.com/ratelimit/storm_mode_active` (GAUGE BOOL)
- **Verified Operations:**
  - Endpoints `/control/cloud/monitoring` and `/control/metrics` provide real-time metric snapshots for monitoring pipelines and dashboards.
