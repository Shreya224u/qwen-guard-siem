from typing import Dict, Any, List

from sqlalchemy.orm import Session

from app.models.log_entry import LogEntry
from app.schemas.unified_event import UnifiedEvent


def save_normalized_event(
    db: Session,
    event: UnifiedEvent | Dict[str, Any],
) -> LogEntry:

    if isinstance(event, UnifiedEvent):
        event_data = event.model_dump()
    else:
        event_data = event

    log_entry = LogEntry(
        timestamp=event_data["timestamp"],
        source=event_data["source"],
        event_type=event_data["event_type"],
        username=event_data.get("username"),
        ip_address=event_data.get("ip_address"),
        device=event_data.get("device"),
        severity=event_data["severity"],
        platform=event_data.get("platform"),
        country=event_data.get("country"),
        raw_log=str(event_data.get("raw_log", "")),
        source_file=event_data.get("source_file"),
    )

    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    return log_entry


def save_normalized_events(
    db: Session,
    events: List[UnifiedEvent | Dict[str, Any]],
) -> int:

    log_entries = []

    for event in events:

        if isinstance(event, UnifiedEvent):
            event_data = event.model_dump()
        else:
            event_data = event

        log_entries.append(
            LogEntry(
                timestamp=event_data["timestamp"],
                source=event_data["source"],
                event_type=event_data["event_type"],
                username=event_data.get("username"),
                ip_address=event_data.get("ip_address"),
                device=event_data.get("device"),
                severity=event_data["severity"],
                platform=event_data.get("platform"),
                country=event_data.get("country"),
                raw_log=str(event_data.get("raw_log", "")),
                source_file=event_data.get("source_file"),
            )
        )

    try:
        db.add_all(log_entries)
        db.commit()

        return len(log_entries)

    except Exception:
        db.rollback()
        raise


def insert_unified_events(
    events: List[UnifiedEvent | Dict[str, Any]],
) -> int:

    from app.db.postgres import SessionLocal

    db = SessionLocal()

    try:
        return save_normalized_events(db, events)

    finally:
        db.close()