import logging
import time

from fastapi import (APIRouter,Depends,UploadFile,File,HTTPException,Query,BackgroundTasks,)
from sqlalchemy import insert
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.models.log_entry import LogEntry
from app.models.alert import Alert
from app.ml.models.audit_log import AuditLog
from app.ml.models.user import User
from app.schemas.log import LogListResponse, LogUploadResponse
from app.services.log_parser_service import parse_file_content
from app.services.normalization_service import normalize
from app.services import rule_engine_service
from app.services import ml_service
from app.services.alert_investigation_service import (
    investigate_alerts_batch,
)

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
                        investigate_alerts_batch,
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
        message=(
            "Logs ingested, normalized, and evaluated by "
            "Rule + ML engines. Automatic investigation "
            "scheduled in the background."
        ),
        filename=file.filename,
        logs_parsed=saved,
        logs_failed=failed,
        alerts_created=alerts_created,
    )


# ============================================================
# GET LOGS
# ============================================================

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

    query = db.query(LogEntry)

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