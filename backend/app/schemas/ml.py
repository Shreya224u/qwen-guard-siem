from pydantic import BaseModel


class MLMetrics(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    data_source: str      # "synthetic" or "real" — always check this before quoting the numbers
    training_rows: int