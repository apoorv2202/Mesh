"""Local-only API. Run with VADER_ENV=development and bind to 127.0.0.1."""
import os
from ipaddress import ip_address
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from .models.security_event import SecurityEvent
from .detectors.rules import Finding, detect_threats
from .risk.engine import RiskResult, score_risk


class AnalysisResponse(BaseModel):
    findings: list[Finding]
    risk: RiskResult


class HealthResponse(BaseModel):
    status: str


class ServiceResponse(BaseModel):
    service: str
    phase: int
    scope: str


def create_app() -> FastAPI:
    development = os.getenv("VADER_ENV", "").lower() == "development"
    app = FastAPI(title="VADER Phase 1", docs_url="/docs" if development else None,
                  redoc_url=None, openapi_url="/openapi.json" if development else None)

    @app.get("/", response_model=ServiceResponse)
    def information():
        return ServiceResponse(service="VADER", phase=1, scope="Local synthetic-event analysis")

    @app.get("/health", response_model=HealthResponse)
    def health():
        return HealthResponse(status="ok")

    @app.post("/api/v1/vader/analyze", response_model=AnalysisResponse)
    def analyze(event: SecurityEvent, request: Request):
        try:
            local = request.client is not None and ip_address(request.client.host).is_loopback
        except ValueError:
            local = False
        if not development or not local:
            raise HTTPException(status_code=403, detail="Analysis requires development mode and a direct loopback client")
        findings = detect_threats(event)
        return AnalysisResponse(findings=findings, risk=score_risk(findings))

    return app


app = create_app()
