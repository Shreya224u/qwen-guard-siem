from typing import Optional, Dict
from sqlalchemy.orm import Session

from app.models.mitre_technique import MitreTechnique


# ---------------------------------------------------------------------------
# STATIC MITRE ATT&CK MAPPING
# ---------------------------------------------------------------------------

STATIC_MAPPING: Dict[str, Dict[str, str]] = {

    "brute_force": {"technique_id": "T1110","name": "Brute Force","tactic": "Credential Access","description": ("Repeated login attempts to guess valid credentials."),},

    "sql_injection": {"technique_id": "T1190","name": "Exploit Public-Facing Application","tactic": "Initial Access","description": ("Exploitation of a vulnerability in an internet-facing ""application, such as through malicious SQL input."),},

    "port_scan": {"technique_id": "T1046","name": "Network Service Discovery","tactic": "Discovery","description": ("Probing network ports and services to identify available ""network resources."),},
    
    "ddos": {"technique_id": "T1498","name": "Network Denial of Service","tactic": "Impact","description": ("Flooding network traffic intended to degrade or deny ""availability of a service."),},

    "malware": {"technique_id": "T1204","name": "User Execution","tactic": "Execution","description": ("Malicious content is executed through user interaction ""with a file, link, or other content."),},

    "unauthorized_access": {"technique_id": "T1078","name": "Valid Accounts","tactic": "Initial Access","description": ("Use of legitimate but compromised or misused credentials "
"to gain access."
        ),
    },

    "powershell_activity": {
        "technique_id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": (
            "Use of PowerShell commands or scripts to execute activity "
            "on a system."
        ),
    },

    # process_creation is intentionally not mapped here.
    #
    # "Process Creation" is an observable behavior rather than a single
    # MITRE ATT&CK technique. Mapping it to an arbitrary technique would
    # create an inaccurate ATT&CK relationship.
}


# ---------------------------------------------------------------------------
# MITRE TECHNIQUE DATABASE CACHE
# ---------------------------------------------------------------------------

_code_to_dbid: Dict[str, int] = {}


# ---------------------------------------------------------------------------
# SEED MITRE TECHNIQUES
# ---------------------------------------------------------------------------

def seed_mitre_techniques(db: Session) -> None:
    """
    Idempotently seed the MITRE techniques used by this SIEM.

    Existing techniques are not duplicated.

    After seeding, the in-memory cache is rebuilt so the Rule Engine and
    ML Engine can perform MITRE lookups without database queries.
    """

    existing_codes = {
        row.technique_id
        for row in db.query(MitreTechnique.technique_id).all()
    }

    for info in STATIC_MAPPING.values():

        technique_id = info["technique_id"]

        if technique_id in existing_codes:
            continue

        db.add(
            MitreTechnique(
                technique_id=technique_id,
                name=info["name"],
                tactic=info["tactic"],
                description=info["description"],
            )
        )

        existing_codes.add(technique_id)

    db.commit()

    load_cache(db)


# ---------------------------------------------------------------------------
# LOAD MITRE CACHE
# ---------------------------------------------------------------------------

def load_cache(db: Session) -> None:
    """
    Load MITRE technique database IDs into memory.

    Example:

        T1110    -> 1
        T1190    -> 2
        T1046    -> 3

    This allows alert creation to avoid a PostgreSQL query for every
    detected event.
    """

    global _code_to_dbid

    _code_to_dbid = {
        row.technique_id: row.id
        for row in db.query(MitreTechnique).all()
    }


# ---------------------------------------------------------------------------
# GET DATABASE ID FOR EVENT TYPE
# ---------------------------------------------------------------------------

def get_db_id_for_event_type(
    event_type: str,
) -> Optional[int]:
    """
    Return the mitre_techniques.id associated with an event_type.

    This function performs ZERO database queries.

    Returns:
        Integer database ID when a mapping exists.
        None when the event type has no MITRE mapping.
    """

    mapping = STATIC_MAPPING.get(event_type)

    if not mapping:
        return None

    technique_id = mapping["technique_id"]

    return _code_to_dbid.get(technique_id)