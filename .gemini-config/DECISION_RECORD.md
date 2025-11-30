# Architecture Decision Records (ADR) & Rejected Patterns

## ADR-001: Instrumentation Strategy
* **Decision:** Use Frida (dynamic instrumentation) over Accessibility Services or OCR.
* **Rationale:** Accessibility services require UI rendering (slow). OCR requires bitmap transfer (extremely slow). Frida reads heap memory before rendering.
* **Decision:** Rust via PyO3.
* **Rationale:** Python Garbage Collection pauses are non-deterministic and can exceed 10ms. Rust guarantees consistent execution time for high-frequency filtering.

## ADR-003: Runtime Interaction Strategy
* **Decision:** Use "Attach Mode" (Late Injection) instead of "Spawn Mode" (Early Injection).
* **Rationale:** The target application (WordSynk v3+) implements anti-tamper checks during `Application.onCreate()`. Spawning the process with a debugger attached causes an immediate crash/segfault. Attaching *after* initialization bypasses these checks.

## Rejected Patterns (Anti-Patterns)

### 1. Shell-based Input (`input tap`)
* **Decision:** Use "Attach Mode" (Late Injection) instead of "Spawn Mode" (Early Injection).
* **Rationale:** The target application (WordSynk v3+) implements anti-tamper checks during `Application.onCreate()`. Spawning the process with a debugger attached causes an immediate crash/segfault. Attaching *after* initialization bypasses these checks.
* **Trade-off:** We miss the initial WebSocket handshake, but we gain 100% stability. Data synchronization is handled by forcing a UI refresh (Pull-to-Refresh) post-attach.

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

### 4. x86 Emulation (Houdini/Translation)
* **Status:** REJECTED (Critical)
* **Technical Reason:** Frida's Java Bridge fails to initialize in translated environments (ARM APK on x86 Emulator).
* **Impact:** `ReferenceError: 'Java' is not defined` loops.
* **Requirement:** Native ARM64 Host (Apple Silicon) + ARM64 AVD + Google APIs Image.

### 5. Runtime SSL Pinning Bypass
* **Status:** REJECTED
* **Technical Reason:** Android 15 networking internals have hardened. Generic "Universal" bypass scripts cause native segfaults when hooked early.
* **Mitigation:** Inject the MITM CA Certificate into the System Trust Store (`/system/etc/security/cacerts`) using Root access. This negates the need for runtime hooking.

### 4. x86 Emulation (Houdini/Translation)
* **Status:** REJECTED (Critical)
* **Technical Reason:** Frida's Java Bridge fails to initialize in translated environments (ARM APK on x86 Emulator).
* **Impact:** `ReferenceError: 'Java' is not defined` loops.
* **Requirement:** Native ARM64 Host (Apple Silicon) + ARM64 AVD + Google APIs Image.

diff --git a/.gemini-config/AGENT_METRICS.yaml b/.gemini-config/AGENT_METRICS.yaml
