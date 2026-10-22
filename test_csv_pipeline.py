from pathlib import Path

from app.schemas.unified_event import UnifiedEvent
from app.services.log_parser_services_csv import parse_csv_content
from app.services.normalisation_services_csv import normalize_csv_event


base_dir = Path(__file__).resolve().parent
csv_files = list(base_dir.glob("*.csv"))

print(f"CSV files found: {len(csv_files)}")

for csv_path in csv_files:
    print(f"\nProcessing: {csv_path.name}")

    content = csv_path.read_text(encoding="utf-8", errors="replace")
    parsed_rows = parse_csv_content(content)

    print(f"Rows parsed: {len(parsed_rows)}")

    for row in parsed_rows[:3]:
        normalized = normalize_csv_event(row)
        event = UnifiedEvent(**normalized)

        print("\nUnified event:")
        print(event.model_dump())