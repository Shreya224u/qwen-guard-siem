from pathlib import Path

from app.db.postgres import SessionLocal
from app.models.log_entry import LogEntry


BASE_DIR = Path(__file__).resolve().parent


db = SessionLocal()

try:
    deleted_count = (
        db.query(LogEntry)
        .filter(
            LogEntry.source == "network_csv",
            LogEntry.source_file == "cybersecurity.csv",
            LogEntry.id > 10000,
        )
        .delete(synchronize_session=False)
    )

    db.commit()

    print(f"Deleted duplicate records: {deleted_count}")

finally:
    db.close()