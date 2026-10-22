from sqlalchemy import Column, Integer, String, Text
from app.db.base import Base

class MitreTechnique(Base):
    """
    Reference table for MITRE ATT&CK techniques.

    Techniques are seeded at application startup and referenced by alerts
    through Alert.mitre_technique_fk.
    """

    __tablename__ = "mitre_techniques"

    # ---------------------------------------------------------
    # Primary Key
    # ---------------------------------------------------------

    id = Column( Integer, primary_key=True, index=True,)

    # ---------------------------------------------------------
    # MITRE ATT&CK Information
    # ---------------------------------------------------------

    technique_id = Column( String(50), unique=True, index=True, nullable=False,)

    name = Column( String(255), nullable=False, )

    tactic = Column( String(100), nullable=False,)

    description = Column( Text, nullable=True )

