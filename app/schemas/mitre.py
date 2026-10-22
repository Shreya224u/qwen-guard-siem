from pydantic import BaseModel
from typing import List, Optional


class MitreTechniqueOut(BaseModel):
    id: int
    technique_id: str
    name: str
    tactic: str
    description: Optional[str]

    class Config:
        from_attributes = True


class MitreTechniqueListResponse(BaseModel):
    total: int
    techniques: List[MitreTechniqueOut]