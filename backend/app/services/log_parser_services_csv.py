import csv
import io
from pathlib import Path
from typing import List, Dict, Any


REQUIRED_COLUMNS = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "bytes_sent",
    "bytes_received",
    "user_agent",
    "url",
    "is_internal_traffic",
    "label",
    "attack_type",
}


def parse_csv_content(content: str) -> List[Dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(content))

    if not reader.fieldnames:
        raise ValueError("CSV file does not contain headers")

    # Clean headers
    reader.fieldnames = [
        field.strip().lower().replace("\ufeff", "")
        for field in reader.fieldnames
    ]

    missing_columns = REQUIRED_COLUMNS - set(reader.fieldnames)

    if missing_columns:
        raise ValueError(
            f"Missing required CSV columns: {', '.join(sorted(missing_columns))}"
        )

    rows = []

    for row in reader:
        cleaned_row = {
            key.strip().lower().replace("\ufeff", ""): (
                value.strip() if isinstance(value, str) else value
            )
            for key, value in row.items()
            if key is not None
        }

        if not any(cleaned_row.values()):
            continue

        rows.append(cleaned_row)

    return rows


def parse_csv_file(file_path: str) -> List[Dict[str, Any]]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {file_path}")

    content = path.read_text(encoding="utf-8-sig")

    return parse_csv_content(content)