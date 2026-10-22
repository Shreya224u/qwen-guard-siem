from sqlalchemy.orm import Session
from sqlalchemy import insert

from app.models.log_entry import LogEntry
from app.models.alert import Alert
from app.ml.models.audit_log import AuditLog

from app.services.log_parser_service import parse_file_content
from app.services.normalization_service import normalize
from app.services import rule_engine_service
from app.services import ml_service

from app.db.postgres import SessionLocal


BATCH_SIZE = 10000


def process_logs_background(
    content: str,
    filename: str,
    username: str,
    job_id: str,
):
    """
    Process uploaded logs in the background.

    This function runs independently from the HTTP request.
    """

    db: Session = SessionLocal()

    try:

        print(f"[{job_id}] Background processing started")

        # Step 1: Parse

        parsed_lines = parse_file_content(
            content,
            filename,
        )

        total_logs = len(parsed_lines)

        print(
            f"[{job_id}] Parsed {total_logs} logs"
        )

        # Step 2: Normalize in batches
     
        logs_failed = 0
        logs_saved = 0
        alerts_created = 0

        # Process directly in chunks instead of storing everything
        # in memory at once.

        for batch_start in range(
            0,
            len(parsed_lines),
            BATCH_SIZE,
        ):

            parsed_batch = parsed_lines[
                batch_start: batch_start + BATCH_SIZE
            ]

            normalized_batch = []

            for parsed in parsed_batch:

                try:

                    normalized = normalize(parsed)

                    normalized_batch.append(normalized)

                except Exception:

                    logs_failed += 1


            if not normalized_batch:
                continue
           
            # Step 3: Insert logs

            stmt = (
                insert(LogEntry)
                .returning(LogEntry.id)
            )

            result = db.execute(
                stmt,
                normalized_batch,
            )

            log_ids = [
                row[0]
                for row in result
            ]

            logs_saved += len(log_ids)

            # Step 4: Rule Engine
        
            rule_alerts = []

            for normalized, log_id in zip(
                normalized_batch,
                log_ids,
            ):

                alert_data = rule_engine_service.evaluate(
                    normalized,
                    log_id,
                )

                if alert_data:
                    rule_alerts.append(alert_data)

            # Step 5: ML Engine
          
            already_flagged = {
                alert["log_id"]
                for alert in rule_alerts
            }

            ml_alerts = ml_service.evaluate_batch(
                normalized_batch,
                log_ids,
                skip_ids=already_flagged,
            )

            # Step 6: Save Alerts
           
            all_alerts = rule_alerts + ml_alerts

            if all_alerts:

                db.execute(
                    insert(Alert),
                    all_alerts,
                )
                
                alerts_created += len(all_alerts)

            # Commit every batch
            db.commit()

            print(
                f"[{job_id}] "
                f"Processed {min(batch_start + BATCH_SIZE, total_logs)}"
                f"/{total_logs}"
            )

        # Step 7: Audit Log
      
        db.add(
            AuditLog(
                user=username,
                action="upload_logs",
                target=filename,
            )
        )

        db.commit()

        print(
            f"[{job_id}] Completed successfully"
        )

        print(
            f"Saved: {logs_saved}, "
            f"Failed: {logs_failed}, "
            f"Alerts: {alerts_created}"
        )

    except Exception as exc:
        db.rollback()
        print(
            f"[{job_id}] Background processing failed: {exc}"
        )

    finally:

        db.close()