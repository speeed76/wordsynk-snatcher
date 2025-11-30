// offer_logger.ts – Ported from "moj_mitmweb_forwarder.js"
// Status: KNOWN WORKING LOGIC
// Adapts the functional SSL Bypass + Sniffers to send data to Python

if (typeof Java === "undefined") {
    send({ type: "LOG", payload: "[CRITICAL] Java missing. Ensure app is running before attaching." });
} else {
    Java.perform(main);
}

function main() {
    send({ type: "LOG", payload: "[+] Hook loaded. Applying SSL Bypass & Sniffers..." });

    // ───── 1. Universal SSL Pinning Bypass (From your working script) ─────
    try {
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function() {
            return this.verifyChain.apply(this, arguments);
        };
    } catch(e) {}
    try {
        const OkHttpClientBuilder = Java.use('okhttp3.OkHttpClient$Builder');
        OkHttpClientBuilder.prototype.certificatePinner.implementation = function() { return this; };
    } catch(e) {}
    try {
        const CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    } catch(e) {}
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        // @ts-ignore
        Java.registerClass({
            name: 'com.fake.FakeTrustManager',
            superClass: Java.use('java.lang.Object'),
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function() {},
                checkServerTrusted: function() {},
                getAcceptedIssuers: function() { return []; }
            }
        });
    } catch(e) {}

    // ───── 2. HTTP Sniffer (OkHttp3 ResponseBody) ─────
    try {
        const ResponseBody = Java.use('okhttp3.ResponseBody');
        // Hook string() to capture the response body
        ResponseBody.string.implementation = function () {
            const result = this.string();
            
            // Basic noise filtering (ignore short/empty responses)
            if (result.length > 10) {
                // Check if it looks like JSON
                if (result.trim().startsWith("{") || result.trim().startsWith("[")) {
                    // Check for booking-specific keywords to reduce traffic
                    if (result.includes("bookingReference") || result.includes("requirements") || result.includes("jobId")) {
                        send(JSON.stringify({
                            type: "HTTP_SNIFF",
                            payload: result
                        }));
                    }
                }
            }
            return result;
        };
        console.log("[+] OkHttp3 Sniffer attached");
    } catch (e) {
        console.log("[!] OkHttp3 error: " + e);
    }

    // ───── 3. WebSocket Sniffer (RealWebSocket) ─────
    try {
        const RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');
        RealWebSocket.onReadMessage.implementation = function (message: any) {
            // Check if message is text (JSON)
            if (typeof message === 'string' && (message.startsWith("{") || message.startsWith("["))) {
                send(JSON.stringify({
                    type: "WS_IN",
                    payload: message
                }));
            }
            return this.onReadMessage(message);
        };
        console.log("[+] WebSocket Sniffer attached");
    } catch (e) {
        console.log("[!] WebSocket error: " + e);
    }
}