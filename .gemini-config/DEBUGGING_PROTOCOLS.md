# Debugging Protocols & Heuristics

## 1. The "Ghost Process" Heuristic
**Symptom:** `ReferenceError: 'Java' is not defined` immediately upon script load.
**Cause:** Frida attached to a native-only subprocess (e.g., `:pushservice`, `:crashhandler`) or a Zygote fork that has not initialized the Android Runtime (ART).
**Protocol:**
1.  **Stop patching code.** The code is likely fine; the target is wrong.
2.  **Request Reconnaissance:** Ask the user to run `adb shell "ps -A | grep <app_name>"`.
3.  **Refine Target:** The main UI process almost *never* has a colon (`:`) in its name. Update the Python selector to filter `if ":" not in proc.name`.

## 2. The "Silent Failure" Protocol
**Symptom:** Frida injects successfully (`Attached to PID...`) but no messages appear, or expected hooks never fire.
**Cause:** Log suppression in the orchestrator or Protocol Mismatch.
**Protocol:**
1.  **Unmute:** Immediately switch the Supervisor logger to `DEBUG` level.
2.  **Ping:** Inject a `send({type: "LOG", ...})` at the very top of the Frida script to prove the bridge is active.
3.  **Check Protocol:** Verify the TypeScript `send({ type: "X" })` matches the Python `if msg["type"] == "X"`.

## 3. The "Lazy Loader" Trap
**Symptom:** `Java.use("com.example.Class")` throws `ClassNotFoundException` on startup, but the class definitely exists in the APK.
**Cause:** Android uses lazy loading. The class is not in memory until the user navigates to that specific screen.
**Protocol:**
* **Do not use:** `Java.perform(() => { ... })` for UI classes on startup.
* **Do use:** `Java.choose` or hook `RecyclerView.setAdapter` or `ClassLoader.loadClass` to catch the class *when* it loads.
* **Better:** Hook lower-level libraries (`okhttp3`, `android.ui.View`) that are always present.

## 4. The "Manual Override" Rule
**Trigger:** If 2 consecutive patches fail to produce a change in debug output.
**Action:** Pause development. Instruct the user to verify the runtime state via `adb shell` or `frida-ps -U`. Do not guess at a 3rd patch.

## 5. Emulator Architecture Mismatch (The "Houdini" Glitch)
**Symptom:** Attached to correct PID, but `Java` is undefined.
**Context:** Running ARM APKs on x86 Emulators.
**Cause:** Frida injects into the x86 Native Bridge instead of the Internal Dalvik VM.
**Action:**
1.  Restart `frida-server` on device.
2.  Reboot Emulator.
3.  If persistent, use an ARM64 native device or `Google APIs` image (not `Google Play`).
