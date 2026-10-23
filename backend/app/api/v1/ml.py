from fastapi import APIRouter, Depends

from app.api.deps import get_current_user, require_admin
from app.schemas.ml import MLMetrics

router = APIRouter(prefix="/ml", tags=["Machine Learning"])


@router.get("/metrics", response_model=MLMetrics)
def get_metrics(current_user=Depends(get_current_user)):
    from app.ml import predict as ml_predict
    return ml_predict.get_metrics()


@router.post("/retrain", response_model=MLMetrics)
def retrain(current_user=Depends(require_admin)):
    from app.ml import predict as ml_predict
    return ml_predict.retrain()
