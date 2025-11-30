### LLM-to-LLM Critical Handover Document
**Target Environment (as of 29 Nov 2025)**
- Android 15 (API 35) google_apis arm64-v8a emulator
- Android Studio Emulator 36.1.9+
- Frida 17.5.1 (host + device)
- Rooted via toybox su + writable-system
- Goal: Full HTTPS + WebSocket interception of com.wordsynknetwork.moj (MOJ) with blobs visible in mitmweb

**Execute exactly in this order – every step is mandatory and order-dependent**

```bash
# 1. AVD creation (once)
echo "no" | avdmanager create avd \
  --name pixel_35_clean \
  --package "system-images;android-35;google_apis;arm64-v8a" \
  --device "pixel_8" \
  --tag google_apis \
  --sdcard 1G \
  --force

# 2. Always launch emulator with these flags
emulator -avd pixel_35_clean -writable-system -gpu host -memory 6144 -cores 8 -no-snapshot-load &

# 3. One-time root prep (verity must be disabled before first boot after wipe)
adb root
adb disable-verity
adb reboot
adb root
adb remount   # /system now permanently RW

# 4. Install mitmproxy CA system-wide (do this after the above reboot)
hashed=$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem $hashed.0
adb push $hashed.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/$hashed.0
adb reboot

# 5. Install MOJ split APK bundle (once)
adb install-multiple apks/*.apk

# 6. Frida-server 17.5.1 arm64 setup (run every fresh session)
adb shell "pkill frida-server || true"
curl -L -o frida-server.xz [https://github.com/frida/frida/releases/download/17.5.1/frida-server-17.5.1-android-arm64.xz](https://github.com/frida/frida/releases/download/17.5.1/frida-server-17.5.1-android-arm64.xz)
unxz -f frida-server.xz
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "su 0 /data/local/tmp/frida-server" &   # toybox su syntax – THIS WORKS

# 7. Verify server is alive
sleep 3
frida-ps -U | wc -l   # must return >200 processes

# 8. Global proxy for full visibility
adb shell settings put global http_proxy 10.0.2.2:8080

# 9. Start mitmweb (host)
mitmweb -k   # -k accepts our self-signed CA
```

**Critical notes that break everything if ignored**
- Never use `su -c` on emulator – toybox su only accepts `su 0 /path/binary`
- Never use spawn (`-f`) without gadget-patched APK – attach with PID instead
- Never skip the verity-disable + reboot cycle – CA won’t be trusted otherwise
- Always download frida-server with the exact URL ending in `-android-arm64.xz` and unxz it

**Result**
- System-wide trusted mitmproxy CA
