📦
5637 /src/frida_hooks/offer_logger.js
3545 /src/frida_hooks/offer_logger.js.map
✄
// src/frida_hooks/offer_logger.ts
rpc.exports = {
  init: () => {
    console.log("[*] WordSynk Snatcher Frida hook active \u2013 watching for new offers");
  }
};
function reflectiveSerializer(javaObj) {
  const data = {};
  const fields = javaObj.class.getDeclaredFields();
  fields.forEach((field) => {
    field.setAccessible(true);
    const name = field.getName();
    try {
      const value = field.get(javaObj);
      if (value !== null) {
        const strVal = value.toString();
        data[name] = strVal;
      } else {
        data[name] = null;
      }
    } catch (e) {
      data[name] = "[Error retrieving]";
    }
  });
  return data;
}
Java.perform(() => {
  const OfferAdapter = Java.use("com.wordsynk.network.moj.ui.offers.OfferListAdapter");
  OfferAdapter.bindViewHolder.overload("androidx.recyclerview.widget.RecyclerView$ViewHolder", "int").implementation = function(holder, position) {
    const result = this.bindViewHolder(holder, position);
    try {
      const offer = this.getItem(position);
      if (offer) {
        const data = {
          detected_at: Date.now(),
          offer_id: offer.getId?.()?.toString() || "unknown",
          price_gbp: offer.getTotalPrice?.() || 0,
          language_pair: offer.getLanguagePair?.() || "unknown",
          postcode: offer.getPostcode?.() || "unknown",
          miles: offer.getDistanceMiles?.() || -1,
          view_bounds: holder.itemView ? {
            x: holder.itemView.getX(),
            y: holder.itemView.getY(),
            width: holder.itemView.getWidth(),
            height: holder.itemView.getHeight()
          } : null
        };
        send(JSON.stringify({
          type: "NEW_OFFER",
          data
        }));
        console.log(`[NEW OFFER] \xA3${data.price_gbp} | ${data.language_pair} | ${data.postcode} | ${data.miles}mi | id=${data.offer_id}`);
        if (data.view_bounds) {
          send(JSON.stringify({
            type: "CLAIM_READY",
            data: {
              offer_id: data.offer_id,
              price_gbp: data.price_gbp,
              language_pair: data.language_pair,
              postcode: data.postcode,
              miles: data.miles,
              bounds: data.view_bounds
            }
          }));
        }
      }
    } catch (e) {
      console.log("[!] Hook error (safe): " + e);
    }
    return result;
  };
  try {
    const BookingAdapter = Java.use("com.wordsynk.network.moj.ui.bookings.BookingListAdapter");
    BookingAdapter.bindViewHolder.overload("androidx.recyclerview.widget.RecyclerView$ViewHolder", "int").implementation = function(holder, position) {
      const result = this.bindViewHolder(holder, position);
      try {
        const booking = this.getItem(position);
        if (booking) {
          const fullData = reflectiveSerializer(booking);
          const payload = {
            type: "NEW_BOOKING",
            data: {
              id: fullData.id || fullData.bookingId || "unknown",
              // These keys are guesses; the reflection dump will reveal the real ones
              start_time: fullData.startDate || fullData.startTime || fullData.start,
              end_time: fullData.endDate || fullData.endTime || fullData.end,
              raw_dump: fullData
            }
          };
          send(JSON.stringify(payload));
        }
      } catch (e) {
        console.log("[!] Booking hook error: " + e);
      }
      return result;
    };
    console.log("[+] BookingListAdapter hook installed");
  } catch (e) {
    console.log("[!] Could not find BookingListAdapter. Check class name.");
  }
  send(JSON.stringify({
    type: "LOG",
    payload: "[+] Hooks initialized. Java.perform executed successfully."
  }));
  try {
    const ResponseBody = Java.use("okhttp3.ResponseBody");
    ResponseBody.string.implementation = function() {
      const responseBodyString = this.string();
      try {
        if (responseBodyString.includes("booking") || responseBodyString.includes("jobId")) {
          send(JSON.stringify({
            type: "HTTP_SNIFF",
            payload: responseBodyString
          }));
          console.log("[Network] Captured potential booking data");
        }
      } catch (e) {
      }
      return responseBodyString;
    };
    console.log("[+] OkHttp3 Interceptor active");
  } catch (e) {
    console.log("[!] OkHttp3 hook error (Obfuscation?): " + e);
  }
  try {
    const RecyclerView = Java.use("androidx.recyclerview.widget.RecyclerView");
    RecyclerView.setAdapter.implementation = function(adapter) {
      if (adapter) {
        const name = adapter.class.getName();
        send(JSON.stringify({
          type: "ADAPTER_FOUND",
          data: { name }
        }));
      }
      this.setAdapter(adapter);
    };
    console.log("[+] RecyclerView discovery hook active");
  } catch (e) {
    console.log("[!] RecyclerView hook error: " + e);
  }
  try {
    const ResponseBody = Java.use("okhttp3.ResponseBody");
    ResponseBody.string.implementation = function() {
      const responseBodyString = this.string();
      try {
        if (responseBodyString.startsWith("{") || responseBodyString.startsWith("[")) {
          if (responseBodyString.includes("booking") || responseBodyString.includes("job") || responseBodyString.includes("start")) {
            send(JSON.stringify({
              type: "HTTP_SNIFF",
              payload: responseBodyString
            }));
          }
        }
      } catch (e) {
      }
      return responseBodyString;
    };
    console.log("[+] OkHttp3 Interceptor active");
  } catch (e) {
    console.log("[!] OkHttp3 hook error: " + e);
  }
});

✄
{
  "version": 3,
  "sources": ["src/frida_hooks/offer_logger.ts"],
  "mappings": "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",
  "names": []
}
