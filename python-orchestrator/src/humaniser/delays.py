import random
import time
from loguru import logger

def human_delay(base: float = 0.0) -> None:
    extra = random.gauss(0, 0.08)
    total = max(0.0, base + extra)
    if total > 0:
        logger.debug(f"Human delay {total:.3f}s")
        time.sleep(total)

def occasional_long_think() -> None:
    if random.random() < 0.04:  # 1 in 25 jobs
        delay = random.uniform(1.4, 2.1)
        logger.info(f"Thinking... {delay:.2f}s")
        time.sleep(delay)

def should_miss() -> bool:
    return random.random() < 0.02  # 2% of suitable jobs ignored

def fake_activity() -> None:
    if random.random() < 0.05:  # ~3× per hour
        logger.debug("Fake activity – tab switch")
        # placeholder for future ADB tab switch
        time.sleep(random.uniform(2.0, 6.0))
