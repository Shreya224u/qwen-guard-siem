import csv
import io
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional


IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
ISO_TIMESTAMP_RE = re.compile(
    r'(?<!\d)\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'
    r'(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?',
    re.IGNORECASE,
)
APACHE_TIMESTAMP_RE = re.compile(
    r'\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s*[+-]\d{4})?'
)
SYSLOG_TIMESTAMP_RE = re.compile(r'\b[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b')
LABELED_TIMESTAMP_RE = re.compile(
    r'\b(?:timestamp|datetime|epochtime|event_time|time_created)\s*[=:]\s*[\"\']?([^\s,;\"\']+)',
    re.IGNORECASE,
)
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


def _utc_naive(value: datetime) -> datetime:
    """Store datetimes as naive UTC because LogEntry.timestamp is timezone-naive."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _parse_timestamp_value(value: str) -> Optional[datetime]:
    raw = value.strip().strip("\"'").rstrip(",;")
    if not raw:
        return None

    # Epoch columns are common in network and Windows exports.
    if re.fullmatch(r"\d{9,17}(?:\.\d+)?", raw):
        try:
            epoch = float(raw)
            if epoch > 10_000_000_000:
                epoch /= 1000
            return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None

    iso_value = raw[:-1] + "+00:00" if raw[-1:].lower() == "z" else raw
    try:
        parsed = datetime.fromisoformat(iso_value)
        if parsed.year >= 1900:
            return _utc_naive(parsed)
    except ValueError:
        pass

    for fmt in (
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%Y/%m/%d %H:%M:%S",
    ):
        try:
            return _utc_naive(datetime.strptime(raw, fmt))
        except ValueError:
            continue

    try:
        # Syslog timestamps omit the year; use the current year and adjust
        # around New Year when the timestamp would otherwise be in the future.
        parsed = datetime.strptime(raw, "%b %d %H:%M:%S").replace(year=datetime.now(timezone.utc).year)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if parsed > now + timedelta(days=1):
            parsed = parsed.replace(year=parsed.year - 1)
        return parsed
    except ValueError:
        return None


def parse_source_timestamp(text: str) -> Optional[datetime]:
    """Return a recognized event timestamp, normalized to naive UTC."""
    if not text:
        return None

    labeled = LABELED_TIMESTAMP_RE.search(text)
    if labeled:
        value = _parse_timestamp_value(labeled.group(1))
        if value is not None:
            return value

    for pattern in (ISO_TIMESTAMP_RE, APACHE_TIMESTAMP_RE, SYSLOG_TIMESTAMP_RE):
        match = pattern.search(text)
        if match:
            value = _parse_timestamp_value(match.group())
            if value is not None:
                return value
    return None


def parse_timestamp(text: str) -> datetime:
    # Missing source timestamps use ingestion time; alert responses separately
    # distinguish this fallback from a real event timestamp.
    return parse_source_timestamp(text) or datetime.now(timezone.utc).replace(tzinfo=None)


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

        # Keep every CSV column in the normalized raw record. Message, subject,
        # sender, body, and spam/ham labels are commonly stored outside the
        # Windows event columns and are needed by downstream detection rules.
        raw_log = " ".join(
            f"{key}={value}"
            for key, value in cleaned.items()
            if value not in (None, "")
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
                "source": (source_name or channel or "Windows event").strip(),
                "device": cleaned.get("computer_name") or "",
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
            "source": src_ip if src_ip != "0.0.0.0" else "Network traffic",
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
