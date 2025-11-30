# WordSynk App Internals & Instrumentation Guide

## Network Architecture
The application relies on standard Java HTTP libraries rather than native code for networking, making it susceptible to high-level Java instrumentation.

### Core Libraries
* **Library:** `okhttp3`
* **Usage:** REST API calls and WebSocket connections.

### Validated Hook Targets
These classes have been confirmed to exist and are not obfuscated in the target version (Probe v10).

#### 1. HTTP Response Capture
* **Target:** `okhttp3.ResponseBody`
* **Method:** `string()`
* **Value:** Returns the raw JSON response body as a String.
* **Strategy:** Hook this to capture `{"bookings": [...]}` payloads before the UI processes them.

#### 2. WebSocket Interception
* **Target:** `okhttp3.OkHttpClient`
* **Method:** `newWebSocket(Request, WebSocketListener)`
* **Value:** Exposes the WSS URL and the Listener object.
* **Strategy:** Hook this to clone the session or inject messages into the live socket stream.

## Data Models
* **Bookings:** Transmitted as JSON objects over HTTP/1.1.
* **Offers:** Pushed via WebSocket (instant) or polled via HTTP (fallback).

**Recommendation:** Prefer `okhttp3` hooks over UI/Adapter hooks for stability across app updates.
