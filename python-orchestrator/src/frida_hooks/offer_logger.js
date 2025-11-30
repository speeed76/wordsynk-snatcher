📦
2616 /src/frida_hooks/offer_logger.js
1828 /src/frida_hooks/offer_logger.js.map
✄
// src/frida_hooks/offer_logger.ts
if (typeof Java === "undefined") {
  send({ type: "LOG", payload: "[CRITICAL] Java missing. Ensure app is running before attaching." });
} else {
  Java.perform(main);
}
function main() {
  send({ type: "LOG", payload: "[+] Hook loaded. Applying SSL Bypass & Sniffers..." });
  try {
    const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function() {
      return this.verifyChain.apply(this, arguments);
    };
  } catch (e) {
  }
  try {
    const OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
    OkHttpClientBuilder.prototype.certificatePinner.implementation = function() {
      return this;
    };
  } catch (e) {
  }
  try {
    const CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function() {
    };
  } catch (e) {
  }
  try {
    const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    Java.registerClass({
      name: "com.fake.FakeTrustManager",
      superClass: Java.use("java.lang.Object"),
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function() {
        },
        checkServerTrusted: function() {
        },
        getAcceptedIssuers: function() {
          return [];
        }
      }
    });
  } catch (e) {
  }
  try {
    const ResponseBody = Java.use("okhttp3.ResponseBody");
    ResponseBody.string.implementation = function() {
      const result = this.string();
      if (result.length > 10) {
        if (result.trim().startsWith("{") || result.trim().startsWith("[")) {
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
  try {
    const RealWebSocket = Java.use("okhttp3.internal.ws.RealWebSocket");
    RealWebSocket.onReadMessage.implementation = function(message) {
      if (typeof message === "string" && (message.startsWith("{") || message.startsWith("["))) {
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

✄
{
  "version": 3,
  "sources": ["src/frida_hooks/offer_logger.ts"],
  "mappings": ";AAIA,IAAI,OAAO,SAAS,aAAa;AAC7B,OAAK,EAAE,MAAM,OAAO,SAAS,mEAAmE,CAAC;AACrG,OAAO;AACH,OAAK,QAAQ,IAAI;AACrB;AAEA,SAAS,OAAO;AACZ,OAAK,EAAE,MAAM,OAAO,SAAS,qDAAqD,CAAC;AAGnF,MAAI;AACA,UAAM,mBAAmB,KAAK,IAAI,4CAA4C;AAC9E,qBAAiB,YAAY,iBAAiB,WAAW;AACrD,aAAO,KAAK,YAAY,MAAM,MAAM,SAAS;AAAA,IACjD;AAAA,EACJ,SAAQ,GAAG;AAAA,EAAC;AACZ,MAAI;AACA,UAAM,sBAAsB,KAAK,IAAI,8BAA8B;AACnE,wBAAoB,UAAU,kBAAkB,iBAAiB,WAAW;AAAE,aAAO;AAAA,IAAM;AAAA,EAC/F,SAAQ,GAAG;AAAA,EAAC;AACZ,MAAI;AACA,UAAM,oBAAoB,KAAK,IAAI,2BAA2B;AAC9D,sBAAkB,MAAM,SAAS,oBAAoB,gBAAgB,EAAE,iBAAiB,WAAW;AAAA,IAAC;AAAA,EACxG,SAAQ,GAAG;AAAA,EAAC;AACZ,MAAI;AACA,UAAM,mBAAmB,KAAK,IAAI,gCAAgC;AAElE,SAAK,cAAc;AAAA,MACf,MAAM;AAAA,MACN,YAAY,KAAK,IAAI,kBAAkB;AAAA,MACvC,YAAY,CAAC,gBAAgB;AAAA,MAC7B,SAAS;AAAA,QACL,oBAAoB,WAAW;AAAA,QAAC;AAAA,QAChC,oBAAoB,WAAW;AAAA,QAAC;AAAA,QAChC,oBAAoB,WAAW;AAAE,iBAAO,CAAC;AAAA,QAAG;AAAA,MAChD;AAAA,IACJ,CAAC;AAAA,EACL,SAAQ,GAAG;AAAA,EAAC;AAGZ,MAAI;AACA,UAAM,eAAe,KAAK,IAAI,sBAAsB;AAEpD,iBAAa,OAAO,iBAAiB,WAAY;AAC7C,YAAM,SAAS,KAAK,OAAO;AAG3B,UAAI,OAAO,SAAS,IAAI;AAEpB,YAAI,OAAO,KAAK,EAAE,WAAW,GAAG,KAAK,OAAO,KAAK,EAAE,WAAW,GAAG,GAAG;AAEhE,cAAI,OAAO,SAAS,kBAAkB,KAAK,OAAO,SAAS,cAAc,KAAK,OAAO,SAAS,OAAO,GAAG;AACpG,iBAAK,KAAK,UAAU;AAAA,cAChB,MAAM;AAAA,cACN,SAAS;AAAA,YACb,CAAC,CAAC;AAAA,UACN;AAAA,QACJ;AAAA,MACJ;AACA,aAAO;AAAA,IACX;AACA,YAAQ,IAAI,8BAA8B;AAAA,EAC9C,SAAS,GAAG;AACR,YAAQ,IAAI,wBAAwB,CAAC;AAAA,EACzC;AAGA,MAAI;AACA,UAAM,gBAAgB,KAAK,IAAI,mCAAmC;AAClE,kBAAc,cAAc,iBAAiB,SAAU,SAAc;AAEjE,UAAI,OAAO,YAAY,aAAa,QAAQ,WAAW,GAAG,KAAK,QAAQ,WAAW,GAAG,IAAI;AACrF,aAAK,KAAK,UAAU;AAAA,UAChB,MAAM;AAAA,UACN,SAAS;AAAA,QACb,CAAC,CAAC;AAAA,MACN;AACA,aAAO,KAAK,cAAc,OAAO;AAAA,IACrC;AACA,YAAQ,IAAI,gCAAgC;AAAA,EAChD,SAAS,GAAG;AACR,YAAQ,IAAI,0BAA0B,CAAC;AAAA,EAC3C;AACJ;",
  "names": []
}
