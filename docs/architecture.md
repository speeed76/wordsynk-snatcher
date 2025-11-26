# Architecture Overview

```
┌───────────────┐    bincode RPC    ┌────────────────┐    ADB    ┌──────────────┐
│   Frida TS    ├──────────────────►│   Python       ├──────────►│   Android    │
│ (on device)   │   offer + bounds  │ Orchestrator   │   taps    │   Emulator   │
└───────────────┘                   └────────────────┘           └──────────────┘
                                          │
                                    Rust Decision Engine
                                          │
                                    Humaniser + Telegram
```

### Core principles
- No XML dumps → Frida gives exact View bounds instantly
- No scrolling → direct coordinate taps on hidden Accept button
- No polling → pure push via existing WebSocket
- Decision in < 1 µs (Rust, zero alloc)
- Total claim latency target: ≤ 580 ms

### Modules (never touched again once accepted)
- `rust-core/snatcher-decision` → pure logic, 100 % tested
- `python-orchestrator/src/frida_hooks` → versioned .ts hooks
- `python-orchestrator/src/adb_controller` → triple-tap engine
- `python-orchestrator/src/humaniser` → behavioural realism
- `python-orchestrator/src/config` → hot-reload TOML

See docs/threat-model.md for detection evasion.
