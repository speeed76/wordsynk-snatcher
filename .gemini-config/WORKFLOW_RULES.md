# Development Standards & Workflow

## 1. Code Generation
* **Format:** All code mutations must be provided as valid `diff` blocks.
* **Application:** Assume usage of `scripts/smart_apply.sh`. Do not provide manual copy-paste instructions unless requested.

## 2. Compilation & Build
* **TypeScript:** Changes to `*.ts` files trigger a mandatory compilation step.
    * Command: `npx frida-compile src/frida_hooks/offer_logger.ts -o src/frida_hooks/offer_logger.js -T none`
    * Context: Must be run from `python-orchestrator/`.

## 3. Testing
* **Rust:** Changes to `rust-core` must pass `cargo test`.
* **Safety:** Configuration must default to `dry_run = true` unless explicitly overriding for a deployment task.

## 4. Context Awareness
* **Pre-flight:** Read `DECISION_RECORD.md` before suggesting architectural changes.
* **Calibration:** Read `AGENT_METRICS.yaml` to adjust tone and output density.

## 5. TypeScript/Frida Protocol
* **Complexity Limit:** If a `.ts` file update changes logic flow (e.g., adding polling), REWRITE the whole file. Do not patch.
* **Environment Check:** Before debugging code, verify `frida --version` matches `adb shell /data/local/tmp/frida-server --version`.

## 6. Infrastructure Prerequisite
* **Native Only:** Development MUST occur on an ARM64 Host with an ARM64 AVD.
* **Root Required:** `adb root` must be available and verified before running orchestrators.
