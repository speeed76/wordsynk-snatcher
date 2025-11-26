from pathlib import Path
import tomlkit
from pydantic import BaseModel
from loguru import logger

class Filters(BaseModel):
    min_price_gbp: float = 70.0
    languages: list[str] = ["Polish", "Romanian"]
    max_miles: int = 60
    blacklist_postcodes: list[str] = []
    dry_run: bool = True

class Config:
    def __init__(self, path: Path = Path("python-orchestrator/config.toml")):
        self.path = path
        self.filters = Filters()
        self._load()

    def _load(self):
        if not self.path.exists():
            logger.warning("Config not found – creating default")
            self._create_default()
        with open(self.path) as f:
            data = tomlkit.parse(f.read())
            self.filters = Filters(**data.get("filters", {}))
        logger.info(f"Config loaded: {self.filters}")

    def _create_default(self):
        default = {
            "filters": {
                "min_price_gbp": 70.0,
                "languages": ["Polish"],
                "max_miles": 60,
                "blacklist_postcodes": [],
                "dry_run": True,
            }
        }
        with open(self.path, "w") as f:
            f.write(tomlkit.dumps(default))

    def reload(self):
        logger.info("Hot-reloading config...")
        self._load()

    def should_claim(self, offer: dict) -> bool:
        if self.filters.dry_run:
            return False
        price = float(offer.get("total", 0))
        lang = offer.get("language_pair", "")
        miles = offer.get("miles", 999)
        postcode = offer.get("postcode", "").upper()

        if price < self.filters.min_price_gbp:
            return False
        if not any(l in lang for l in self.filters.languages):
            return False
        if miles > self.filters.max_miles:
            return False
        if any(pc in postcode for pc in self.filters.blacklist_postcodes):
            return False
        return True
