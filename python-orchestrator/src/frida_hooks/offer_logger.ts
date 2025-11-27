// offer_logger.ts – LIVE, zero-claim, sub-50ms offer detection
// Attach with: frida -U -f com.wordsynknetwork.moj -l offer_logger.ts --no-pause

rpc.exports = {
    init: () => {
        console.log("[*] WordSynk Snatcher Frida hook active – watching for new offers");
    }
};

Java.perform(() => {
    // Hook the real OfferAdapter (confirmed via JADX on v1.0.15)
    const OfferAdapter = Java.use("com.wordsynk.network.moj.ui.offers.OfferListAdapter");

    OfferAdapter.bindViewHolder.overload('androidx.recyclerview.widget.RecyclerView$ViewHolder', 'int').implementation = function (holder, position) {
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
                        height: holder.itemView.getHeight(),
                    } : null
                };

                // Send to Python supervisor instantly
                send(JSON.stringify({
                    type: "NEW_OFFER",
                    data: data
                }));

                console.log(`[NEW OFFER] £${data.price_gbp} | ${data.language_pair} | ${data.postcode} | ${data.miles}mi | id=${data.offer_id}`);

                // Send bounds for claiming
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

    console.log("[+] OfferListAdapter hook installed");
});
