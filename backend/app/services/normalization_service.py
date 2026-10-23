from typing import Dict, Any


# ---------------------------------------------------------------------------
# COMMON EVENT SCHEMA
# ---------------------------------------------------------------------------
#
# Every log source is converted into the same normalized structure so that
# Rules, ML, MITRE mapping, and PostgreSQL all receive consistent data.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# SEVERITY KEYWORDS
# ---------------------------------------------------------------------------

SEVERITY_KEYWORDS = {
    "critical": (
        "critical",
        "emergency",
        "fatal",
        "root login",
        "privilege escalation",
    ),
    "high": (
        "error",
        "failed",
        "brute",
        "attack",
        "malware",
        "ddos",
        "injection",
    ),
    "medium": (
        "warning",
        "warn",
        "unauthorized",
        "suspicious",
        "multiple failed",
    ),
    "low": (
        "info",
        "notice",
        "accepted",
        "success",
        "connected",
    ),
}


# ---------------------------------------------------------------------------
# EVENT TYPE KEYWORDS
# ---------------------------------------------------------------------------

EVENT_TYPE_KEYWORDS = {
    # Message indicators take precedence over generic auth/security words that
    # can also appear inside a phishing email's subject or body.
    "spam_phishing": (
        "spam",
        "phishing",
        "phishing email",
        "phishing attempt",
        "suspicious email",
        "bulk email",
        "malicious email",
        "spoofed email",
        "credential harvesting",
        "suspicious attachment",
        "verify your account",
        "account suspended",
        "urgent action required",
        "click here to verify",
        "claim your reward",
        "won a prize",
        "password expires",
        "you have won",
        "you've won",
        "claim your prize",
        "cash prize",
        "free gift",
        "gift card",
        "limited time offer",
        "act now",
        "urgent payment",
        "reset your password",
    ),
    "brute_force": (
        "failed password",
        "authentication failure",
        "invalid user",
        "event_id=4625",
        "event_id=4771",
        "event_id=4776",
    ),
    "sql_injection": (
        "union select",
        "drop table",
        "1=1",
        " or 1",
    ),
    "port_scan": (
        "port scan",
        "nmap",
        "masscan",
        "syn flood",
    ),
    "ddos": (
        "ddos",
        "flood",
        "udp flood",
    ),
    "malware": (
        "malware",
        "virus",
        "trojan",
        "ransomware",
    ),
    "unauthorized_access": (
        "unauthorized",
        "privilege escalation",
        "event_id=4672",
        "event_id=1102",
        "event_id=4720",
        "event_id=4726",
        "event_id=4697",
        "event_id=7045",
    ),
    "powershell_activity": (
        "event_id=4104",
        "powershell",
    ),
    "process_creation": (
        "event_id=4688",
    ),
    "login_success": (
        "accepted password",
        "login successful",
        "event_id=4624",
    ),
}


# ---------------------------------------------------------------------------
# COUNTRY PREFIX MAP
# ---------------------------------------------------------------------------

COUNTRY_PREFIX_MAP = (
    ("192.168", "Local"),
    ("10.", "Local"),
    ("172.", "Local"),
    ("185.", "Ukraine"),
    ("91.", "Netherlands"),
    ("46.", "Germany"),
    ("103.", "India"),
    ("5.", "Russia"),
    ("1.", "China"),
    ("104.", "USA"),
    ("8.", "USA"),
    ("216.", "USA"),
)


# ---------------------------------------------------------------------------
# PRE-COMPUTED LOOKUPS
# ---------------------------------------------------------------------------
#
# Lowercase keyword tuples avoid rebuilding/converting data for every log.
# The tuples also make the configuration immutable during processing.
# ---------------------------------------------------------------------------

_SEVERITY_RULES = tuple(
    (severity, keywords)
    for severity, keywords in SEVERITY_KEYWORDS.items()
)

_EVENT_RULES = tuple(
    (event_type, keywords)
    for event_type, keywords in EVENT_TYPE_KEYWORDS.items()
)


# ---------------------------------------------------------------------------
# SEVERITY CLASSIFICATION
# ---------------------------------------------------------------------------

def classify_severity(raw_log: str) -> str:
    """
    Determine severity from the raw log.

    The order is intentional:
        critical -> high -> medium -> low

    The first matching severity wins, preserving the original behaviour.
    """

    if not raw_log:
        return "low"

    return _classify_severity_text(raw_log.lower())


def _classify_severity_text(text: str) -> str:

    for severity, keywords in _SEVERITY_RULES:
        for keyword in keywords:
            if keyword in text:
                return severity

    return "low"


# ---------------------------------------------------------------------------
# EVENT TYPE CLASSIFICATION
# ---------------------------------------------------------------------------

def classify_event_type(raw_log: str) -> str:
    """
    Determine the normalized event type.

    The first matching event rule wins, preserving the original behaviour.
    """

    if not raw_log:
        return "general"

    return _classify_event_type_text(raw_log.lower())


def _classify_event_type_text(text: str) -> str:

    for event_type, keywords in _EVENT_RULES:
        for keyword in keywords:
            if keyword in text:
                return event_type

    return "general"


# ---------------------------------------------------------------------------
# COUNTRY CLASSIFICATION
# ---------------------------------------------------------------------------

def guess_country(ip: str) -> str:
    """
    Perform the existing lightweight prefix-based country classification.

    This is intentionally not treated as real GeoIP data.
    """

    if not ip:
        return "Unknown"

    for prefix, country in COUNTRY_PREFIX_MAP:
        if ip.startswith(prefix):
            return country

    return "Unknown"


# ---------------------------------------------------------------------------
# NORMALIZATION
# ---------------------------------------------------------------------------

def normalize(parsed_line: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert one parsed log into the normalized LogEntry structure.

    The returned dictionary matches the LogEntry database columns.
    """

    raw_log = parsed_line.get("raw_log") or ""
    ip = parsed_line.get("ip_address") or ""
    platform = parsed_line.get("platform") or "unknown"
    source = parsed_line.get("source") or platform.lower()

    # Both classifiers scan the same raw line. Lowercase once instead of
    # allocating a second full copy for each log during large uploads.
    raw_log_lower = raw_log.lower()
    event_type = _classify_event_type_text(raw_log_lower) if raw_log_lower else "general"
    severity = _classify_severity_text(raw_log_lower) if raw_log_lower else "low"

    return {
        "timestamp": parsed_line.get("timestamp"),
        "source": source,
        "event_type": event_type,
        "username": parsed_line.get("username"),
        "ip_address": ip,
        "device": parsed_line.get("device") or platform,
        "severity": severity,
        "platform": platform,
        "country": guess_country(ip),
        "raw_log": raw_log,
        "source_file": parsed_line.get("source_file"),
    }
