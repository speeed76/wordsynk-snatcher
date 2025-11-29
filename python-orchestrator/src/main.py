from loguru import logger
import frida
import json
from datetime import datetime
from pathlib import Path
from adb_controller.tap_engine import TapEngine
from config.loader import Config
from storage.db import BookingDb

config = Config()
tap_engine = TapEngine()
db = BookingDb()


def on_message(message, _data):
    if message["type"] == "log":
        logger.info(f"FRIDA: {message['payload']}")


def on_message(message, _data):
    # DEBUG: Dump everything to see if we are missing events
    logger.debug(f"RAW MSG: {message}")

    if message["type"] == "send":
        payload = message["payload"]
        msg = json.loads(payload)
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

        elif msg["type"] == "HTTP_RESPONSE":
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
    logger.add(lambda msg: print(msg, flush=True), level="INFO", colorize=True)
    logger.info("WordSynk Snatcher LIVE – waiting for offers...")
    logger.info(
        "This hook sees jobs the millisecond the server pushes them – before UI render"
    )

    device = frida.get_usb_device(timeout=10)
    # Robust attach – works whether app is running or not
    try:
        session = device.attach("com.wordsynknetwork.moj")
        logger.success("Attached to WordSynk by name")
    except frida.ProcessNotFoundError:
        # Fallback: find any process containing "wordsynk"
        procs = [
            p for p in device.enumerate_processes() if "wordsynk" in p.name.lower()
        ]
        if not procs:
            logger.error("No WordSynk process found – is the app open?")
            return
        session = device.attach(procs[0].pid)
        logger.success(f"Attached to WordSynk (PID {procs[0].pid}) via fallback")
    except frida.InvalidOperationError as e:
        logger.error(f"Frida attach failed: {e}")
        return

    script_path = Path(__file__).parent / "frida_hooks" / "offer_logger.js"
    with open(script_path, "r", encoding="utf-8") as f:
        script = session.create_script(f.read())
    script.on("message", on_message)
    script.load()
    logger.success("Frida offer logger + claim engine active")
    logger.info("dry_run = True → change to False in config.toml when ready")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        logger.info("Shutting down")


if __name__ == "__main__":
    main()
