from __future__ import annotations
import time
import random
from loguru import logger
from ppadb.client import Client as AdbClient

class TapEngine:
    def __init__(self, device_serial: str = "emulator-5554"):
        client = AdbClient(host="127.0.0.1", port=5037)
        self.device = client.device(device_serial)
        if not self.device:
            raise RuntimeError(f"Device {device_serial} not found")

    def tap(self, x: int, y: int, duration_ms: int | None = None) -> None:
        duration = duration_ms or random.randint(60, 140)
        jitter_x = random.randint(-12, 12)
        jitter_y = random.randint(-12, 12)
        final_x, final_y = x + jitter_x, y + jitter_y
        logger.debug(f"Tap at ({final_x}, {final_y}) duration={duration}ms")
        self.device.shell(f"input tap {final_x} {final_y}")
        time.sleep(duration / 1000.0)

    def triple_tap_sequence(
        self,
        card_x: int,
        card_y: int,
        accept_x: int,
        accept_y: int,
        modal_accept_x: int = 540,
        modal_accept_y: int = 920,
    ) -> None:
        self.tap(card_x, card_y)
        time.sleep(random.uniform(0.18, 0.24))
        self.tap(accept_x, accept_y)
        time.sleep(random.uniform(0.09, 0.15))
        self.tap(modal_accept_x, modal_accept_y)
        logger.success("Claim sequence executed")

    def fake_scroll(self) -> None:
        self.device.shell("input swipe 500 1600 500 400 400")
        time.sleep(random.uniform(1.2, 3.8))
