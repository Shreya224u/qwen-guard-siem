from datetime import datetime
from typing import Dict, Any

from app.schemas.unified_event import UnifiedEvent


def parse_csv_timestamp(value: str) -> datetime:
    value = value.strip()

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    raise ValueError(f"Unsupported timestamp format: {value}")


def classify_network_event(row: Dict[str, Any]) -> str:
    dst_port = int(row["dst_port"])
    protocol = row["protocol"].upper()
    url = row.get("url", "").lower()

    if dst_port in [22, 23, 3389]:
        return "Remote Access Traffic"

    if dst_port in [445, 139]:
        return "File Sharing Traffic"

    if dst_port in [1433, 3306, 5432]:
        return "Database Traffic"

    if protocol == "UDP":
        return "UDP Network Traffic"

    if any(keyword in url for keyword in ["login", "auth", "owa", "webmail"]):
        return "Web Authentication Traffic"

    return "General Network Traffic"


def calculate_initial_severity(row: Dict[str, Any]) -> str:
    dst_port = int(row["dst_port"])
    bytes_sent = int(row["bytes_sent"])
    bytes_received = int(row["bytes_received"])

    if dst_port in [22, 23, 3389, 445, 139]:
        return "medium"

    if bytes_sent > 1_000_000 or bytes_received > 1_000_000:
        return "medium"

    return "low"


def normalize_csv_event(row: Dict[str, Any]) -> Dict[str, Any]:
    is_internal = str(row["is_internal_traffic"]).strip().lower() in {
        "true",
        "1",
        "yes",
    }

    return {
        "timestamp": parse_csv_timestamp(row["timestamp"]),
        "source": "network_csv",
        "event_type": classify_network_event(row),
        "username": "unknown",
        "ip_address": row["src_ip"],
        "device": "Network Sensor",
        "severity": calculate_initial_severity(row),
        "platform": "Network",
        "country": None,
        "raw_log": str(row),
        "source_file": "cybersecurity.csv",
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
        "src_port": int(row["src_port"]),
        "dst_port": int(row["dst_port"]),
        "protocol": row["protocol"],
        "bytes_sent": int(row["bytes_sent"]),
        "bytes_received": int(row["bytes_received"]),
        "user_agent": row["user_agent"],
        "url": row["url"],
        "is_internal_traffic": is_internal,
        "label": row["label"],
        "attack_type": row["attack_type"],
    }


def normalize_csv_row(row: Dict[str, Any]) -> UnifiedEvent:
    normalized_data = normalize_csv_event(row)
    return UnifiedEvent(**normalized_data)