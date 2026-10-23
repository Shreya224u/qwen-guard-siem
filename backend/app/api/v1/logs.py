import logging
import time
from datetime import datetime, timedelta, timezone

from fastapi import (APIRouter,Depends,UploadFile,File,HTTPException,Query,BackgroundTasks,)
from sqlalchemy import func, insert, or_
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.models.log_entry import LogEntry
from app.models.alert import Alert
from app.ml.models.audit_log import AuditLog
from app.ml.models.user import User
from app.schemas.log import (
    LogListResponse,
    LogUploadDeleteResponse,
    LogUploadHistoryItem,
    LogUploadResponse,
)
from app.services.log_parser_service import parse_file_content
from app.services.log_parser_service import parse_source_timestamp
from app.services.normalization_service import normalize
from app.services.normalization_service import classify_event_type
from app.services import rule_engine_service


def run_alert_investigation_batch(alert_ids):
    # Investigation uses the ML stack; defer importing it until an upload
    # actually schedules investigation work.
    from app.services.alert_investigation_service import investigate_alerts_batch
    investigate_alerts_batch(alert_ids)

router = APIRouter(
    prefix="/logs",
    tags=["Logs"],
)

logger = logging.getLogger("siem.upload")

# Larger batches reduce PostgreSQL round trips.
LOG_BATCH_SIZE = 10000

# Alerts are investigated after the HTTP response is returned.
INVESTIGATION_BATCH_SIZE = 500

@router.post(
    "/upload",
    response_model=LogUploadResponse,
)
async def upload_logs(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
   
    start_time = time.perf_counter()

    content_bytes = await file.read()

    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content = content_bytes.decode("latin-1")

    t0 = time.perf_counter()

    parsed_lines = parse_file_content(
        content,
        file.filename,
    )

    parse_time = time.perf_counter() - t0

    if not parsed_lines:
        raise HTTPException(
            status_code=400,
            detail="No parseable log lines found in this file",
        )

    t0 = time.perf_counter()

    normalized_rows = []
    failed = 0

    # Keep normalization in Python memory, but do not touch DB
    # during this stage.
    for parsed in parsed_lines:
        try:
            normalized_rows.append(
                normalize(parsed)
            )
        except Exception:
            failed += 1

    normalize_time = time.perf_counter() - t0

    if not normalized_rows:
        raise HTTPException(
            status_code=400,
            detail="No valid logs could be normalized",
        )

    # Release parser output as early as possible.
    del parsed_lines

    saved = 0
    alerts_created = 0

    insert_logs_time = 0.0
    rule_engine_time = 0.0
    ml_engine_time = 0.0
    insert_alerts_time = 0.0

    for batch_start in range(
        0,
        len(normalized_rows),
        LOG_BATCH_SIZE,
    ):

        batch_end = min(
            batch_start + LOG_BATCH_SIZE,
            len(normalized_rows),
        )

        batch = normalized_rows[
            batch_start:batch_end
        ]
        # Persist ownership so each account only sees its own uploads.
        batch = [{**row, "user_id": current_user.id} for row in batch]

        logger.info(
            "Processing logs %s-%s of %s",
            batch_start + 1,
            batch_end,
            len(normalized_rows),
        )

        try:
        
            t0 = time.perf_counter()

            stmt = (
                insert(LogEntry)
                .returning(LogEntry.id)
            )

            result = db.execute(
                stmt,
                batch,
            )

            log_ids = [
                row[0]
                for row in result
            ]

            saved += len(log_ids)

            insert_logs_time += (
                time.perf_counter() - t0
            )

            # =================================================
            # STAGE 4 — RULE ENGINE
            # =================================================

            t0 = time.perf_counter()

            # The Rule Engine should process the complete
            # batch rather than calling evaluate() once per log.
            #
            # This is critical for million-log uploads.
            rule_alerts = (
                rule_engine_service.evaluate_batch(
                    batch,
                    log_ids,
                )
            )

            rule_engine_time += (
                time.perf_counter() - t0
            )

            # =================================================
            # STAGE 5 — ML ENGINE
            # =================================================

            t0 = time.perf_counter()

            already_flagged = {
                alert["log_id"]
                for alert in rule_alerts
            }

            from app.services import ml_service
            ml_alerts = (
                ml_service.evaluate_batch(
                    batch,
                    log_ids,
                    skip_ids=already_flagged,
                )
            )

            ml_engine_time += (
                time.perf_counter() - t0
            )

            # =================================================
            # STAGE 6 — BULK INSERT ALERTS
            # =================================================

            all_alerts = (
                rule_alerts +
                ml_alerts
            )

            new_alert_ids = []

            if all_alerts:

                t0 = time.perf_counter()

                stmt = (
                    insert(Alert)
                    .returning(Alert.id)
                )

                result = db.execute(
                    stmt,
                    all_alerts,
                )

                new_alert_ids = [
                    row[0]
                    for row in result
                ]

                alerts_created += len(
                    new_alert_ids
                )

                insert_alerts_time += (
                    time.perf_counter() - t0
                )

            # =================================================
            # COMMIT COMPLETE LOG BATCH
            # =================================================

            db.commit()

            # =================================================
            # STAGE 7 — BACKGROUND INVESTIGATION
            # =================================================

            # Investigation must NOT happen inside the upload
            # transaction. It is CPU/DB work and would make a
            # million-log upload extremely slow.

            if new_alert_ids:

                for investigation_start in range(
                    0,
                    len(new_alert_ids),
                    INVESTIGATION_BATCH_SIZE,
                ):

                    investigation_batch = new_alert_ids[
                        investigation_start:
                        investigation_start
                        + INVESTIGATION_BATCH_SIZE
                    ]

                    background_tasks.add_task(
                        run_alert_investigation_batch,
                        investigation_batch,
                    )

        except Exception:

            db.rollback()

            logger.exception(
                "Failed processing log batch starting at record %s",
                batch_start + 1,
            )

            raise HTTPException(
                status_code=500,
                detail=(
                    f"Failed while processing log batch "
                    f"starting at record {batch_start + 1}"
                ),
            )

    # ========================================================
    # STAGE 8 — AUDIT LOG
    # ========================================================

    try:

        db.add(
            AuditLog(
                user=current_user.username,
                action="upload_logs",
                target=file.filename,
            )
        )

        db.commit()

    except Exception:

        db.rollback()

        logger.exception(
            "Failed to store audit log for %s",
            file.filename,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Logs were processed, but audit information "
                "could not be stored"
            ),
        )

    # ========================================================
    # PERFORMANCE LOGGING
    # ========================================================

    total_time = (
        time.perf_counter() - start_time
    )

    logger.info(
        "UPLOAD TIMING [%s] "
        "total=%.2fs | "
        "parse=%.2fs | "
        "normalize=%.2fs | "
        "insert_logs=%.2fs | "
        "rule_engine=%.2fs | "
        "ml_engine=%.2fs | "
        "insert_alerts=%.2fs | "
        "rows=%s | "
        "alerts=%s | "
        "failed=%s",
        file.filename,
        total_time,
        parse_time,
        normalize_time,
        insert_logs_time,
        rule_engine_time,
        ml_engine_time,
        insert_alerts_time,
        saved,
        alerts_created,
        failed,
    )

    # Release large in-memory structure.
    del normalized_rows

    # ========================================================
    # RESPONSE
    # ========================================================

    return LogUploadResponse(
        message="Upload complete.",
        filename=file.filename,
        logs_parsed=saved,
        logs_failed=failed,
        alerts_created=alerts_created,
    )


# ============================================================
# GET LOGS
# ============================================================

@router.get("/activity")
def get_event_activity(
    range: str = Query(default="24h"),
    source_file: str = Query(default="", max_length=255),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return complete log/alert counts for the selected time window."""
    settings = {
        "24h": (timedelta(hours=24), timedelta(hours=3)),
        "7d": (timedelta(days=7), timedelta(days=1)),
        "30d": (timedelta(days=30), timedelta(days=1)),
        "all": (None, timedelta(days=1)),
    }
    if range not in settings:
        raise HTTPException(status_code=422, detail="Range must be one of: 24h, 7d, 30d, all")

    duration, step = settings[range]
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    window_start = now - duration if duration is not None else None

    def bucket_start(value: datetime) -> datetime:
        if step < timedelta(days=1):
            step_hours = int(step.total_seconds() // 3600)
            return value.replace(hour=(value.hour // step_hours) * step_hours, minute=0, second=0, microsecond=0)
        return value.replace(hour=0, minute=0, second=0, microsecond=0)

    query = (
        db.query(
            LogEntry.id,
            LogEntry.raw_log,
            LogEntry.created_at,
            func.count(Alert.id).label("alert_count"),
        )
        .outerjoin(Alert, Alert.log_id == LogEntry.id)
        .filter(LogEntry.user_id == current_user.id)
    )
    if window_start is not None:
        # Include timestamps stored by the parser plus recently ingested rows
        # whose original source timestamps may need to be re-evaluated.
        candidate_start = window_start - timedelta(days=1)
        candidate_end = now + timedelta(days=1)
        query = query.filter(
            or_(
                LogEntry.timestamp.between(candidate_start, candidate_end),
                LogEntry.created_at.between(candidate_start, candidate_end),
            )
        )
    if source_file:
        query = query.filter(LogEntry.source_file == source_file)

    def empty_bucket(value: datetime):
        return {
            "timestamp": value.isoformat() + "Z",
            "events": 0,
            "threats": 0,
            "ingested_events": 0,
            "ingested_threats": 0,
        }

    counts = {}
    for row in query.group_by(LogEntry.id).yield_per(5000):
        source_time = parse_source_timestamp(row.raw_log or "")
        # Missing/invalid event times are counted separately at ingestion time.
        # They are never mixed into the source-event-time series.
        event_time = source_time or row.created_at
        if event_time is None:
            continue
        if event_time.tzinfo is not None:
            event_time = event_time.astimezone(timezone.utc).replace(tzinfo=None)
        if event_time > now or (window_start is not None and event_time < window_start):
            continue

        bucket_time = bucket_start(event_time)
        bucket = counts.setdefault(bucket_time, empty_bucket(bucket_time))
        if source_time is None:
            bucket["ingested_events"] += 1
            bucket["ingested_threats"] += int(row.alert_count or 0)
        else:
            bucket["events"] += 1
            bucket["threats"] += int(row.alert_count or 0)

    if range == "all" and counts:
        cursor = min(counts)
        last_bucket = max(counts)
        while cursor <= last_bucket:
            counts.setdefault(cursor, empty_bucket(cursor))
            cursor += step
    elif window_start is not None:
        cursor = bucket_start(window_start)
        last_bucket = bucket_start(now)
        while cursor <= last_bucket:
            counts.setdefault(cursor, empty_bucket(cursor))
            cursor += step

    buckets = [counts[key] for key in sorted(counts)]
    return {"range": range, "buckets": buckets}

@router.get(
    "/uploads",
    response_model=list[LogUploadHistoryItem],
)
def get_upload_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List files uploaded by the signed-in user, with their processing totals."""
    rows = (
        db.query(
            LogEntry.source_file.label("filename"),
            func.count(func.distinct(LogEntry.id)).label("logs_count"),
            func.count(Alert.id).label("alerts_count"),
            func.max(LogEntry.created_at).label("last_uploaded_at"),
        )
        .outerjoin(Alert, Alert.log_id == LogEntry.id)
        .filter(
            LogEntry.user_id == current_user.id,
            LogEntry.source_file.isnot(None),
        )
        .group_by(LogEntry.source_file)
        .order_by(func.max(LogEntry.created_at).desc())
        .all()
    )
    return [dict(row._mapping) for row in rows]


@router.delete(
    "/uploads",
    response_model=LogUploadDeleteResponse,
)
def delete_uploaded_file(
    filename: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete this user's stored logs and generated alerts for a filename."""
    log_query = db.query(LogEntry.id).filter(
        LogEntry.user_id == current_user.id,
        LogEntry.source_file == filename,
    )
    log_ids = [row[0] for row in log_query.all()]
    if not log_ids:
        raise HTTPException(status_code=404, detail="Uploaded file not found")

    alerts_deleted = (
        db.query(Alert)
        .filter(Alert.log_id.in_(log_ids))
        .delete(synchronize_session=False)
    )
    logs_deleted = (
        db.query(LogEntry)
        .filter(
            LogEntry.user_id == current_user.id,
            LogEntry.source_file == filename,
        )
        .delete(synchronize_session=False)
    )
    db.add(AuditLog(user=current_user.username, action="delete_upload", target=filename))
    db.commit()
    return LogUploadDeleteResponse(
        filename=filename,
        logs_deleted=logs_deleted,
        alerts_deleted=alerts_deleted,
    )


@router.post("/uploads/spam-scan")
def scan_uploaded_file_for_spam(
    filename: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Re-run spam/phishing detection on one of this user's uploaded files."""
    logs = (
        db.query(LogEntry)
        .filter(
            LogEntry.user_id == current_user.id,
            LogEntry.source_file == filename,
        )
        .order_by(LogEntry.id.asc())
        .all()
    )
    if not logs:
        raise HTTPException(status_code=404, detail="Uploaded file not found")

    existing_ids = {
        row[0]
        for row in db.query(Alert.log_id)
        .join(LogEntry, Alert.log_id == LogEntry.id)
        .filter(
            LogEntry.user_id == current_user.id,
            LogEntry.source_file == filename,
            Alert.alert_type == "Spam / Phishing Message",
        )
        .all()
    }

    candidates = []
    candidate_ids = []
    for log in logs:
        if log.id in existing_ids:
            continue
        if classify_event_type(log.raw_log or "") != "spam_phishing":
            continue
        candidates.append({
            "event_type": "spam_phishing",
            "ip_address": log.ip_address,
            "raw_log": log.raw_log or "",
        })
        candidate_ids.append(log.id)

    alert_rows = rule_engine_service.evaluate_batch(candidates, candidate_ids) if candidates else []
    if alert_rows:
        db.execute(insert(Alert), alert_rows)
        db.add(AuditLog(user=current_user.username, action="spam_scan", target=filename))
        db.commit()

    return {
        "filename": filename,
        "logs_scanned": len(logs),
        "spam_alerts_created": len(alert_rows),
        "spam_alerts_existing": len(existing_ids),
    }

@router.get(
    "",
    response_model=LogListResponse,
)
def get_logs(
    skip: int = Query(
        default=0,
        ge=0,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    severity: str = None,
    platform: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve paginated logs with optional filters.
    """

    query = db.query(LogEntry).filter(LogEntry.user_id == current_user.id)

    if severity:
        query = query.filter(
            LogEntry.severity == severity
        )

    if platform:
        query = query.filter(
            LogEntry.source_platform == platform
        )

    total = query.count()

    logs = (
        query
        .order_by(
            LogEntry.created_at.desc()
        )
        .offset(skip)
        .limit(limit)
        .all()
    )

    return LogListResponse(
        total=total,
        logs=logs,
    )
