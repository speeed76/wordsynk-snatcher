# Architecture Decision Records (ADR) & Rejected Patterns

## ADR-001: Instrumentation Strategy
* **Decision:** Use Frida (dynamic instrumentation) over Accessibility Services or OCR.
* **Rationale:** Accessibility services require UI rendering (slow). OCR requires bitmap transfer (extremely slow). Frida reads heap memory before rendering.

## ADR-002: Decision Engine Language
* **Decision:** Rust via PyO3.
* **Rationale:** Python Garbage Collection pauses are non-deterministic and can exceed 10ms. Rust guarantees consistent execution time for high-frequency filtering.

## Rejected Patterns (Anti-Patterns)

### 1. Shell-based Input (`input tap`)
* **Status:** REJECTED
* **Technical Reason:** Android `input` command initializes a JVM instance for every call.
* **Impact:** 300ms+ latency penalty.
* **Alternative:** Persistent `sendevent` stream or direct Java method invocation.

### 2. UI Polling (XML Dumping)
* **Status:** REJECTED
* **Technical Reason:** `uiautomator` serialization locks the UI thread and takes 1-3 seconds.
* **Impact:** Missed opportunities.

### 3. Blind Git Patching
* **Status:** REJECTED
* **Technical Reason:** LLMs hallucinate context lines, causing `git apply` failures.
* **Impact:** Corrupted source tree.
* **Mitigation:** Mandatory usage of `scripts/smart_apply.sh` with secondary verification agent.

diff --git a/.gemini-config/AGENT_METRICS.yaml b/.gemini-config/AGENT_METRICS.yaml
