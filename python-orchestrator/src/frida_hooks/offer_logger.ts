// offer_logger.ts – safe, zero-claim logging only
// Attach with: frida -U -f com.wordsynknetwork.moj -l offer_logger.ts --no-pause

rpc.exports = {
    init: () => {
        console.log("[*] Frida hook active – logging new offers only");
    }
};

// Example hook – will be expanded in next PR
Java.perform(() => {
    const OfferAdapter = Java.use("com.wordsynk.network.moj.ui.offers.OfferAdapter");
    OfferAdapter.onBindViewHolder.overload('androidx.recyclerview.widget.RecyclerView$ViewHolder', 'int').implementation = function(holder, position) {
        this.onBindViewHolder(holder, position);
        const offer = this.getItem(position);
        if (offer) {
            const json = {
                id: offer.getId?.() || "unknown",
                price: offer.getTotalPrice?.() || 0,
                language: offer.getLanguagePair?.() || "unknown",
                postcode: offer.getPostcode?.() || "unknown",
                bounds: holder.itemView ? {
                    x: holder.itemView.getX(),
                    y: holder.itemView.getY(),
                    width: holder.itemView.getWidth(),
                    height: holder.itemView.getHeight(),
                } : null
            };
            send(JSON.stringify(json));
        }
    };
});
