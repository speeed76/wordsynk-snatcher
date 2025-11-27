import sqlite3
import json
from loguru import logger
from pathlib import Path

class BookingDb:
    def __init__(self, db_name="bookings.sqlite"):
        self.db_path = Path(__file__).parent.parent.parent / db_name
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_table()

    def _init_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS bookings (
            id TEXT PRIMARY KEY,
            start_time TEXT,
            end_time TEXT,
            raw_dump TEXT,
            scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        self.conn.execute(query)
        self.conn.commit()

    def upsert_booking(self, data: dict):
        """
        Insert or update a booking record.
        Expects data to have keys: id, start_time, end_time, raw_dump
        """
        try:
            query = """
            INSERT OR REPLACE INTO bookings (id, start_time, end_time, raw_dump)
            VALUES (?, ?, ?, ?)
            """
            raw_json = json.dumps(data.get("raw_dump", {}))
            self.conn.execute(query, (data["id"], data.get("start_time"), data.get("end_time"), raw_json))
            self.conn.commit()
        except Exception as e:
            logger.error(f"DB Error: {e}")
