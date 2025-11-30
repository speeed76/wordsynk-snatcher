# Development Path Post-Mortem: "The Spawn Trap"

## 1. Failed Approach: Process Spawning
* **Strategy:** Using `frida -f com.wordsynknetwork.moj` (Spawn Mode) to hook SSL classes early.
* **Outcome:** Application crash / Immediate termination.
* **Root Cause:** Android 15 (API 35) + WordSynk v3+ implements runtime integrity checks during `Application.onCreate()`. The presence of a debugger/injector during startup triggers a self-defense termination.
* **Correction:** Switch to **Attach Mode**. Launch app manually (or via `monkey`), wait for initialization, then attach.

## 2. Failed Approach: Universal SSL Pinning Bypass
* **Strategy:** Hooking `com.android.org.conscrypt.TrustManagerImpl` on API 35.
* **Outcome:** Segfault (Native Crash).
* **Root Cause:** Internal Android networking classes have changed significantly in Android 14/15. Generic bypass scripts are dangerous.
* **Correction:** **Infrastructure-level Bypass.** Inject the MITM CA certificate into the System Trust Store (`/system/etc/security/cacerts`) using Root access.

## 3. Failed Approach: x86 Emulation (The "Houdini" Glitch)
* **Strategy:** Running ARM APKs on standard x86 Android Emulators.
* **Outcome:** `ReferenceError: 'Java' is not defined`.
* **Root Cause:** The emulator uses `libhoudini` binary translation. Frida attaches to the x86 wrapper process, not the internal ARM Dalvik VM. The Java Runtime is invisible to the hook.
* **Correction:** **Native ARM64.** Use Apple Silicon (M1/M2/M3) host with `arm64-v8a` AVD images only.
