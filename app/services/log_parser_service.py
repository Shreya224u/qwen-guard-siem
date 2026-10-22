import csv
import io
import re
from datetime import datetime
from typing import List, Dict, Any


IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TIMESTAMP_PATTERNS = [
    re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'),
    re.compile(r'\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}'),
    re.compile(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'),
]
USERNAME_PATTERN = re.compile(
    r'(?:user[=: ]+|username[=: ]+|for\s+)(\w+)',
    re.IGNORECASE,
)


def detect_platform(filename: str, line: str) -> str:
    fname = filename.lower()

    if "magnet" in fname or "windows" in fname:
        return "Windows"
    if "apache" in fname or "GET" in line or "POST" in line:
        return "Apache"
    if "nginx" in fname:
        return "Nginx"
    if "sshd" in line or "auth" in fname:
        return "Linux"
    if "firewall" in fname or "UFW" in line:
        return "Firewall"

    return "Unknown"


def parse_timestamp(text: str) -> datetime:
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(text)

        if match:
            raw = match.group()

            for fmt in [
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S",
            ]:
                try:
                    return datetime.strptime(raw, fmt)
                except ValueError:
                    continue

    return datetime.utcnow()


def parse_line(line: str, filename: str) -> Dict[str, Any]:
    ip_match = IP_PATTERN.search(line)
    user_match = USERNAME_PATTERN.search(line)

    return {
        "raw_log": line.strip(),
        "ip_address": ip_match.group() if ip_match else "0.0.0.0",
        "username": user_match.group(1) if user_match else "unknown",
        "timestamp": parse_timestamp(line),
        "platform": detect_platform(filename, line),
        "source_file": filename,
    }


def parse_windows_csv(content: str, filename: str) -> List[Dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(content))

    if not reader.fieldnames:
        return []

    rows = []

    for row in reader:
        cleaned = {
            (key or "").strip().lower().replace("\ufeff", ""): (
                value.strip() if isinstance(value, str) else value
            )
            for key, value in row.items()
            if key is not None
        }

        if not any(cleaned.values()):
            continue

        timestamp = (
            cleaned.get("timestamp")
            or cleaned.get("datetime")
            or cleaned.get("epochtime")
        )

        source_name = cleaned.get("source_name", "")
        channel = cleaned.get("channel", "")
        event_id = cleaned.get("event_id", "")

        raw_log = (
            f"source_name={source_name} "
            f"channel={channel} "
            f"event_id={event_id} "
            f"datetime={timestamp}"
        )

        rows.append(
            {
                "raw_log": raw_log,
                "ip_address": "0.0.0.0",
               "username": (
    cleaned.get("user_sid")
    if cleaned.get("user_sid") not in (None, "", "None")
    else "unknown"
),
                "timestamp": parse_timestamp(str(timestamp)),
                "platform": "Windows",
                "source_file": filename,
            }
        )

    return rows

def parse_network_csv(content: str, filename: str) -> List[Dict[str, Any]]:
    """Parse network-traffic CSV files while preserving useful fields."""
    reader = csv.DictReader(io.StringIO(content))

    if not reader.fieldnames:
        return []

    rows = []

    for row in reader:
        cleaned = {
            (key or "").strip().lower().replace("\ufeff", ""): (
                value.strip() if isinstance(value, str) else value
            )
            for key, value in row.items()
            if key is not None
        }

        if not any(cleaned.values()):
            continue

        timestamp_text = (
            cleaned.get("timestamp")
            or cleaned.get("datetime")
            or ""
        )

        src_ip = cleaned.get("src_ip") or cleaned.get("source_ip") or "0.0.0.0"

        # Preserve the original network fields for downstream analysis.
        raw_log = " ".join(
            f"{key}={value}"
            for key, value in cleaned.items()
            if value not in (None, "")
        )

        rows.append({
            "raw_log": raw_log,
            "ip_address": src_ip,
            "username": "unknown",
            "timestamp": parse_timestamp(str(timestamp_text)),
            "platform": "Network",
            "source_file": filename,
        })

    return rows


def parse_file_content(content: str, filename: str) -> List[Dict[str, Any]]:
    """Parse network and Windows CSVs; parse other files line by line."""

    if filename.lower().endswith(".csv"):
        reader = csv.DictReader(io.StringIO(content))
        headers = {
            (header or "").strip().lower().replace("\ufeff", "")
            for header in (reader.fieldnames or [])
        }

        if {"src_ip", "dst_ip"}.issubset(headers):
            return parse_network_csv(content, filename)

        return parse_windows_csv(content, filename)

    return [
        parse_line(line, filename)
        for line in content.splitlines()
        if line.strip()
    ]