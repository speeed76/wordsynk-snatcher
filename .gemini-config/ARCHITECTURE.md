# System Architecture & Constraints

## System Objective
Resilient data scraping and automated booking acceptance for the WordSynk Android application.
**Operational Model:** "Hunt & Attach" (Find running process -> Inject -> Scrape).

## Component Architecture


### 1. Instrumentation Layer (Frida/TypeScript)
* **Path:** `python-orchestrator/src/frida_hooks/`
* **Function:** In-memory object interception via `RecyclerView.Adapter`.
* **Function:** Network traffic sniffing via `okhttp3` interception.
* **Constraint:** Must operate in "Attach Mode" to evade anti-tamper checks.
* **Interface:** Async RPC (JSON) to Python Orchestrator.

### 2. Decision Core (Rust)
### 2. Decision Core (Rust)
* **Path:** `rust-core/snatcher-decision/`
* **Function:** Deterministic filtering logic (Price, Distance, Language).
* **Constraint:** Zero allocation during hot path. Execution time < 1ms.
* **Interface:** FFI via `PyO3` (Python Extension).

### 3. Orchestration & I/O (Python)
* **Path:** `python-orchestrator/`
* **Function:** Process lifecycle management, ADB transport, Config I/O.
* **Constraint:** No blocking I/O on the event loop.

### 4. Persistence (SQLite)
* **Path:** Root `bookings.sqlite`
* **Function:** Local cache of scraped booking objects.
* **Schema:** `id` (PK), `start_time`, `end_time`, `raw_blob`.

## Operational Constraints (Adversarial)
1.  **Input Sanitation:** `input tap` spawns a process per event (Latency: ~300ms). This is unacceptable. Use persistent shell pipes or raw `/dev/input` writes.
2.  **Heuristics Evasion:** Interaction patterns must include jitter (humanization) to defeat statistical analysis.
3.  **Atomic Operations:** Claim sequences must not rely on UI state verification between steps due to latency costs.
4.  **Environment Integrity:** The system MUST run on a Native ARM64 environment. Any attempt to use x86 translation layers will cause the instrumentation layer to fail.
4.  **Environment Integrity:** The system MUST run on a Native ARM64 environment. Any attempt to use x86 translation layers will cause the instrumentation layer to fail.

diff --git a/.gemini-config/DECISION_RECORD.md b/.gemini-config/DECISION_RECORD.md
