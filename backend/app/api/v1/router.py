"""Version one API router and the single place to register feature routes."""

from fastapi import APIRouter

from app.api.v1 import account, admin, alerts, auth, auth_verification, feedback, graph, logs, mitre, ml, oauth

api_v1_router = APIRouter()

for feature_router in (
    auth.router,
    auth_verification.router,
    oauth.router,
    account.router,
    logs.router,
    alerts.router,
    ml.router,
    mitre.router,
    graph.router,
    feedback.router,
    admin.router,
):
    api_v1_router.include_router(feature_router)
