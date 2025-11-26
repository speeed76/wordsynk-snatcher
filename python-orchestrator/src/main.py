from loguru import logger
import frida

def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        logger.info(f"New offer: {payload}")

def main():
    logger.remove()
    logger.add(lambda msg: print(msg, flush=True), level="INFO")
    logger.info("WordSynk Snatcher started – dry-run mode")

    try:
        session = frida.attach("com.wordsynknetwork.moj")
        logger.success("Attached to WordSynk")
    except frida.ProcessNotFoundError:
        logger.error("WordSynk not running – start the app first")
        return

    script = session.create_script(open("src/frida_hooks/offer_logger.ts").read())
    script.on("message", on_message)
    script.load()
    logger.info("Frida hook loaded – waiting for offers...")

    # Keep alive
    try:
        while True:
            pass
    except KeyboardInterrupt:
        logger.info("Shutting down")

if __name__ == "__main__":
    main()
