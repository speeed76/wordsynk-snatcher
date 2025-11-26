# Threat Model & Mitigations

| Threat                         | Likelihood | Mitigation                                      | Confidence |
|--------------------------------|------------|--------------------------------------------------|------------|
| Claim < 400 ms                 | Low        | Humaniser adds gaussian + occasional 1–2 s wait | High       |
| Frida/Magisk detection         | Medium     | Shamiko + passive gadget, no frida-server port   | High       |
| Confirmation modal telemetry   | Very Low   | ADB taps force real modal render                 | High       |
| App update breaks hooks        | High       | Fallback to pure ADB + version check             | Medium     |
| Rate-limit / ban               | Low        | Max 1 claim/5 min baseline + burst control       | High       |
| IP/device fingerprint change   | Low        | Run from home IP, rotate emulator quarterly     | High       |

### Behavioural profile (indistinguishable from fast human)
- Tap jitter ±12 px, duration 60–140 ms
- 2–3×/hour fake tab switches + scrolls
- 1–3 % of suitable jobs deliberately ignored
- Random “thinking” delays on 1/25 jobs

### Monitoring
- Telegram alerts on every win
- Auto-pause if >3 failed claims/hour
- Weekly win-rate review vs human baseline
