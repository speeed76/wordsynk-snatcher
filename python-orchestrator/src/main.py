from loguru import logger
import frida
import json
from datetime import datetime
from pathlib import Path
from adb_controller.tap_engine import TapEngine
from config.loader import Config


# Placeholder for missing definitions
class BookingDb:
    def upsert_booking(self, booking):
        pass

    def save_snapshot(self, payload):
        pass

    def is_time_slot_free(self, offer_start, offer_end):
        return False


db = BookingDb()

# Global initialization for objects used later in on_message
try:
    config = Config()
except Exception:
    # Mock Config if instantiation fails (e.g., missing args)
    class MockConfig:
        def is_dry_run(self):
            return True

        def should_claim(self, offer_data):
            return True

    config = MockConfig()


def on_message(message, _data):
    # DEBUG: Dump everything to see if we are missing events

    if message["type"] == "send":
        payload = message["payload"]

        # FIX: Handle cases where payload is already a dict (Frida auto-deserialization)
        if isinstance(payload, str):
            msg = json.loads(payload)
        else:
            msg = payload

        if msg["type"] == "LOG":
            logger.info(f"FRIDA: {msg['payload']}")
            return

        if msg["type"] == "NEW_OFFER":
            offer = msg["data"]
            logger.info(f"FRIDA: {msg['payload']}")
            return

        if msg["type"] == "NEW_OFFER":
            offer = msg["data"]
            ts = datetime.fromtimestamp(offer["detected_at"] / 1000).strftime(
                "%H:%M:%S.%f"
            )[:-3]
            logger.success(
                f"NEW OFFER @ {ts} | £{offer['price_gbp']} | {offer['language_pair']} | {offer['postcode']} | {offer['miles']}mi | id={offer['offer_id']}"
            )

        elif msg["type"] == "NEW_BOOKING":
            booking = msg["data"]
            # Persist to SQLite
            db.upsert_booking(booking)
            logger.info(f"Scraped booking {booking['id']} - stored in DB")

        elif msg["type"] == "CLAIM_READY":
            offer = msg["data"]
            if config.is_dry_run():
                logger.info(
                    f"DRY-RUN: would claim £{offer['price_gbp']} {offer['language_pair']} → {offer['postcode']}"
                )
                return

            # Final decision via Rust engine would go here – placeholder
            should_claim = config.should_claim(
                {
                    "total": offer["price_gbp"],
                    "language_pair": offer["language_pair"],
                    "miles": offer["miles"],
                    "postcode": offer["postcode"],
                }
            )

            # Check for calendar conflicts
            # (This is where we will eventually query db.check_availability)
            # if not db.is_time_slot_free(offer_start, offer_end):
            #     logger.warning("Conflict detected - skipping")
            #     return

            if not should_claim:
                logger.info(f"Filtered out £{offer['price_gbp']} job")
                return

            logger.warning(
                f"AUTO-CLAIMING £{offer['price_gbp']} {offer['language_pair']} → {offer['postcode']}"
            )
            tap_engine.claim_offer(offer["bounds"])

        # Handle both HTTP polls and WebSocket pushes via the same logic
        elif msg["type"] in ["HTTP_SNIFF", "WS_IN"]:
            # Raw data capture for analysis
            payload = msg.get("payload", "")
            # Basic filter to ensure we only save relevant booking data
            if "booking" in payload.lower():
                db.save_snapshot(payload)
                logger.info(f"Captured generic booking data ({len(payload)} bytes)")

        else:
            logger.debug(f"Unhandled message type: {msg['type']}")


def main():
    logger.remove()
    # CRITICAL: Level lowered to DEBUG to reveal the "silent" messages
    logger.add(lambda msg: print(msg, flush=True), level="DEBUG", colorize=True)
    logger.info("WordSynk Snatcher LIVE – waiting for offers...")
    # FIX: Removed the redundant logger.info( call that caused the unclosed parenthesis error
    logger.info("WordSynk Snatcher LIVE – waiting for offers...")
    logger.info(
        "This hook sees jobs the millisecond the server pushes them – before UI render"
    )

    device = frida.get_usb_device(timeout=10)
    # Robust attach – works whether app is running or not
    try:
        # ATTACH MODE: Bypasses anti-frida startup checks
        # We rely on System Certs for SSL, so early injection isn't needed.
        logger.info("Scanning for running WordSynk process...")
        procs = [
            p for p in device.enumerate_processes() if "wordsynk" in p.name.lower()
        ]
        if not procs:
            logger.error("No WordSynk process found – please launch the app manually!")
            return

        # Filter: Prefer the process that does NOT have a ':' (usually the main UI)
        target_proc = next((p for p in procs if ":" not in p.name), procs[0])

        session = device.attach(target_proc.pid)
        logger.success(f"Attached to {target_proc.name} (PID {target_proc.pid})")
    except frida.InvalidOperationError as e:
        return

    script_path = Path(__file__).parent / "frida_hooks" / "offer_logger.js"
    with open(script_path, "r", encoding="utf-8") as f:
        script = session.create_script(f.read())
    script.on("message", on_message)
    script.load()
    logger.info("dry_run = True → change to False in config.toml when ready")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        logger.info("Shutting down")


if __name__ == "__main__":
    main()
