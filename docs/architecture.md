# System Architecture & Threat Model

**Project:** Project 09 · API Under Attack — Stop the Request Storm  
**Program:** BMSCE × MindMatrix Skill Lab Initiative  
**System Name:** CampusShield API Gateway & Adaptive Request Storm Defense  

---

## 1. System Overview

CampusShield is an enterprise-grade API rate limiting and storm shield gateway designed to protect internal academic and campus microservices from application-layer distributed denial-of-service (DDoS) traffic, volumetric request storms, and quota depletion attacks. 

The architecture enforces zero-trust boundaries at the application edge, evaluates client identity and rate limit tier, inspects real-time traffic velocity, and enforces adaptive defensive actions:
- **Token Bucket Limiting:** Smooth burst-tolerant refill for normal operations.
- **Sliding Window Counter:** Prevents boundary double-burst exploitation.
- **Leaky Bucket Queue Shaper:** Enforces strict deterministic inter-arrival pacing.
- **Adaptive Storm Gate:** Dynamically detects volumetric waves (>100 RPS) and unique identity floods, tightening anonymous quotas while prioritizing paying tiers.
- **Stale-While-Revalidate Graceful Degradation:** Serves cached fallbacks on read routes (`GET /api/data`) during high congestion rather than dropping requests.

---

## 2. Architecture & Data Flow

```mermaid
flowchart TD
    subgraph Untrusted["Untrusted External Zone"]
        Client["Client / API Consumer / Attacker"]
    end

    subgraph Edge["Security Perimeter & Trust Boundary"]
        ReverseProxy["Edge / Reverse Proxy (Vercel / Cloud Run)"]
        ShieldMW["ShieldMiddleware (Pure ASGI Engine)"]
        CorrelationEngine["Correlation & Session Engine"]
        IdentityResolver["Identity & Tier Resolver"]
    end

    subgraph DefenseEngine["Defensive Controls Engine"]
        StormDetector["Adaptive Storm Detector (5s Rolling RPS)"]
        GlobalCap["Global Upstream Admission Cap Gate"]
        AlgorithmRouter{"Selected Strategy"}
        TB["Token Bucket"]
        SW["Sliding Window"]
        LB["Leaky Bucket / Queue Shaper"]
        DegradationCache["SWR Cached Fallback Cache"]
    end

    subgraph Telemetry["Observability & Auditing"]
        SecLogger["Cloud Logging Adapter (Sanitized JSON)"]
        MetricsAgg["Cloud Monitoring Adapter & Ring Buffer"]
    end

    subgraph Upstream["Protected Core Services"]
        MockUpstream["Protected Campus APIs (/api/ping, /api/data, /api/heavy-compute)"]
    end

    Client -->|HTTP Request + X-API-Key / Cookie| ReverseProxy
    ReverseProxy --> ShieldMW
    ShieldMW --> CorrelationEngine
    CorrelationEngine --> IdentityResolver
    IdentityResolver --> StormDetector
    StormDetector --> GlobalCap
    
    GlobalCap -->|Under Cap| AlgorithmRouter
    GlobalCap -->|Exceeded| DegradationCache
    
    AlgorithmRouter -->|Token Bucket| TB
    AlgorithmRouter -->|Sliding Window| SW
    AlgorithmRouter -->|Leaky Bucket| LB
    
    TB -->|Allowed| MockUpstream
    SW -->|Allowed| MockUpstream
    LB -->|Shaped Outflow| MockUpstream
    
    TB -->|Throttled| DegradationCache
    SW -->|Throttled| DegradationCache
    LB -->|Queue Overflow| DegradationCache
    
    DegradationCache -->|Cache Hit (GET)| Client
    DegradationCache -->|Cache Miss / POST| Client
    
    ShieldMW -.->|Structured Event| SecLogger
    ShieldMW -.->|Telemetry Points| MetricsAgg
```

---

## 3. Assets & Protected Resources

| Asset | Location / Endpoint | Sensitivity | Protection Mechanism |
|---|---|---|---|
| **Upstream Health Ping** | `GET /api/ping` | Low / Availability | Token cost: 1 token. Monitored for baseline latency. |
| **Campus Analytics Query** | `GET /api/data` | Medium / Performance | Token cost: 2 tokens. SWR Cacheable (`200 Cached-Fallback`). |
| **Heavy Compute Workload** | `POST /api/heavy-compute` | High / CPU & Memory Exhaustion | Token cost: 5 tokens. Non-cacheable write. Strict HTTP 429 rejection. |
| **Control & Defense Tuning** | `/control/*` | High / Admin Integrity | Exempt from rate limiter; requires session isolation or `ADMIN_TOKEN`. |
| **Audit Logs & Telemetry** | Cloud Logging & Monitoring | High / Confidentiality | Masked IPs (`*.*`), masked keys (`API_KEY [PRO]`), zero raw credentials. |

---

## 4. Trust Boundaries & Threat Assumptions

### Boundary 1: External Client to Edge Gateway
- **Assumption:** All incoming requests are untrusted. Headers such as `X-Forwarded-For` are only trusted when arriving from verified loopback or cloud reverse proxy sockets.
- **Threat:** Callers may attempt IP spoofing, header poisoning, or random API key generation.
- **Control:** Unknown API keys do not allocate new storage buckets; they fall back strictly to the client IP bucket, preventing cardinality exhaustion attacks.

### Boundary 2: Gateway to Upstream Core Services
- **Assumption:** Upstream services have limited computational capacity (governed by an upstream concurrency semaphore).
- **Threat:** Unthrottled request spikes saturate connection pools and CPU threads.
- **Control:** Global upstream admission cap gate (60 RPS default) and concurrency semaphore shed lower-tier traffic before upstream overload occurs.

### Boundary 3: Gateway to Logging & Cloud Storage
- **Assumption:** Log streams are exported to Google Cloud Logging and team dashboards.
- **Threat:** Credential harvesting via logs or telemetry screen-shares.
- **Control:** Automatic data scrubbing (`mask_identity` and `sanitize_payload`), stripping passwords, tokens, full request bodies, and personal identifiers.
