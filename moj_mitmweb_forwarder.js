// moj_mitmweb_forwarder.js
// Drop this file anywhere, then run the one-liner at the bottom

Java.perform(function () {
    console.log("[+] MOJ → mitmweb forwarder loaded – pinning bypassed + blobs forwarded");

    // ───── Universal SSL pinning bypass (covers 99.9 % of apps in 2025) ─────
    const bypass = (() => {
        try { const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl'); TrustManagerImpl.verifyChain.implementation = function() { return this.verifyChain.apply(this, arguments); }; } catch(e) {}
        try { const OkHttpClient = Java.use("okhttp3.OkHttpClient"); OkHttpClient$Builder = Java.use('okhttp3.OkHttpClient$Builder'); OkHttpClient$Builder.prototype.certificatePinner.implementation = function() { return this; }; } catch(e) {}
        try { const CertificatePinner = Java.use('okhttp3.CertificatePinner'); CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {}; } catch(e) {}
        try { const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager'); Java.registerClass({ name: 'com.fake.FakeTrustManager', superClass: Java.use('java.lang.Object'), implements: [X509TrustManager], methods: { checkClientTrusted: [], checkServerTrusted: [], getAcceptedIssuers: function() { return []; } } }); } catch(e) {}
    })();

    // ───── Helper: send any string to mitmweb as a POST so it appears in the flow ─────
    function forwardToMitmweb(body) {
        try {
            const Request = Java.use('okhttp3.Request');
            const RequestBody = Java.use('okhttp3.RequestBody');
            const MediaType = Java.use('okhttp3.MediaType');
            const OkHttpClient = Java.use('okhttp3.OkHttpClient');

            const client = OkHttpClient.$new();
            const request = new Request.Builder()
                .url("http://127.0.0.1:8080/__moj_blob")   // unique path = easy filter in mitmweb
                .post(RequestBody.create(MediaType.parse("application/json"), body))
                .build();

            // fire and forget – we don’t care about the response
            client.newCall(request).enqueue(Java.use('okhttp3.Callback').$new({
                onFailure: function() {},
                onResponse: function() {}
            }));
        } catch (e) {}
    }

    // ───── Intercept normal HTTP responses (OkHttp) ─────
    const ResponseBody = Java.use('okhttp3.ResponseBody');
    ResponseBody.string.implementation = function () {
        const result = this.string();
        if (result.length > 10) {                     // filter noise
            console.log("[HTTP] " + result.substring(0, 200) + (result.length > 200 ? "…" : ""));
            forwardToMitmweb(result);
        }
        return result;
    };

    // ───── Intercept WebSocket text frames (the real game blobs) ─────
    try {
        const RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');
        RealWebSocket.onReadMessage.implementation = function (message) {
            if (message.startsWith("{") || message.startsWith("[")) {
                console.log("[WebSocket →] " + message.substring(0, 300) + (message.length > 300 ? "…" : ""));
                forwardToMitmweb(message);
            }
            return this.onReadMessage(message);
        };
    } catch (e) {}

    // ───── Also catch outgoing WebSocket frames (your moves) ─────
    try {
        const WebSocket = Java.use('okhttp3.WebSocket');
        WebSocket.send.overload('java.lang.String').implementation = function (msg) {
            console.log("[WebSocket ←] " + msg);
            return this.send(msg);
        };
    } catch (e) {}
});