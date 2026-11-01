from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from azure.security.vader.models.security_event import SecurityEvent
from azure.security.vader.detectors.rules import detect_threats
from azure.security.vader.correlation.engine import correlate_events
from azure.security.vader.risk.engine import score_risk
from azure.security.vader.main import create_app

ORG = uuid4()
START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(kind="login", details=None, **kwargs):
    return SecurityEvent(organization_id=kwargs.pop("organization_id", ORG),
                         actor_identifier=kwargs.pop("actor_identifier", "alice"), event_type=kind,
                         details=details if details is not None else {}, **kwargs)


def chain():
    return [event(kind, details, event_time=START + timedelta(minutes=i)) for i, (kind, details) in enumerate([
        ("login", {"failed_attempts": 5}), ("privilege_escalation", {"authorized": False}),
        ("sensitive_resource_access", {"authorized": False}), ("data_transfer", {"bytes_transferred": 10**9})])]


@pytest.mark.parametrize("kind,details,code", [
    ("login", {}, None), ("login", {"failed_attempts": 4}, None),
    ("login", {"failed_attempts": 5}, "EXCESSIVE_LOGIN_FAILURES"),
    ("login", {"failed_attempts": 7}, "EXCESSIVE_LOGIN_FAILURES"),
    ("privilege_escalation", {"authorized": True}, None),
    ("privilege_escalation", {"authorized": False}, "UNAUTHORIZED_PRIVILEGE_ESCALATION"),
    ("sensitive_resource_access", {"authorized": True}, None),
    ("sensitive_resource_access", {"authorized": False}, "UNAUTHORIZED_SENSITIVE_ACCESS"),
    ("data_transfer", {"bytes_transferred": 10**9 - 1}, None),
    ("data_transfer", {"bytes_transferred": 10**9}, "LARGE_DATA_TRANSFER")])
def test_rules(kind, details, code):
    findings = detect_threats(event(kind, details))
    assert [f["rule_code"] for f in findings] == ([code] if code else [])
    if code and "UNAUTHORIZED" in code:
        assert findings[0]["severity"] == "critical"


@pytest.mark.parametrize("kind,details", [("login", {"failed_attempts": -1}),
    ("login", {"failed_attempts": True}), ("login", {"failed_attempts": "5"}),
    ("data_transfer", {"bytes_transferred": -1}), ("data_transfer", {"bytes_transferred": 1.5}),
    ("privilege_escalation", {"authorized": "false"}), ("privilege_escalation", {"authorized": 0}),
    ("sensitive_resource_access", {"authorized": None}), ("data_transfer", {}), ("privilege_escalation", {})])
def test_invalid_details(kind, details):
    with pytest.raises(ValidationError):
        event(kind, details)


def test_missing_org():
    with pytest.raises(ValidationError):
        SecurityEvent(event_type="login", actor_identifier="alice")


@pytest.mark.parametrize("kwargs", [{"actor_identifier": "  "}, {"source_ip": "invalid"},
                                    {"event_time": datetime(2026, 1, 1)}])
def test_invalid_fields(kwargs):
    with pytest.raises(ValidationError):
        event(**kwargs)


def test_utc_and_defaults():
    assert event().event_time.utcoffset() == timedelta(0)
    assert event(event_time=START.astimezone(timezone(timedelta(hours=5)))).event_time == START
    a, b = event(), event()
    a.details["other"] = True
    assert "other" not in b.details


def test_complete_chain_and_deduplication():
    events = chain()
    results = correlate_events(events + events)
    assert len(results) == 1
    assert len(results[0]["matched_events"]) == 4
    assert len(results[0]["detection_rules"]) == 4
    assert correlate_events(list(reversed(events))) == results


@pytest.mark.parametrize("field,value", [("organization_id", uuid4()), ("actor_identifier", "bob")])
def test_isolation(field, value):
    events = chain()
    events[2] = events[2].model_copy(update={field: value})
    assert correlate_events(events) == []


def test_wrong_chronology():
    events = chain()
    events[1] = events[1].model_copy(update={"event_time": START - timedelta(minutes=1)})
    assert correlate_events(events) == []


def test_equal_timestamps():
    assert correlate_events([e.model_copy(update={"event_time": START}) for e in chain()]) == []


def test_window():
    assert correlate_events(chain(), timedelta(minutes=2)) == []
    assert len(correlate_events(chain(), timedelta(minutes=3))) == 1
    with pytest.raises(ValueError):
        correlate_events(chain(), timedelta(0))


def test_benign_stage_cannot_complete_chain():
    events = chain()
    events[1] = event("privilege_escalation", {"authorized": True}, event_time=START + timedelta(minutes=1))
    assert correlate_events(events) == []


def test_risk_bounds_and_evidence():
    findings = [f for e in chain() for f in detect_threats(e)]
    result = score_risk(findings, correlate_events(chain()))
    assert 0 <= result.risk_score <= 100
    assert result.risk_score > score_risk(findings).risk_score
    assert score_risk([]).risk_score == 0
    assert score_risk(findings * 100).risk_score == score_risk(findings).risk_score
    assert "not probability" in result.confidence_explanation
    richer = [dict(f, evidence=dict(f["evidence"], source_ip="127.0.0.1")) for f in findings]
    assert score_risk(richer).confidence_estimate > score_risk(findings).confidence_estimate


def test_api(monkeypatch):
    monkeypatch.setenv("VADER_ENV", "development")
    with TestClient(create_app(), client=("127.0.0.1", 12345)) as client:
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/").json()["phase"] == 1
        response = client.post("/api/v1/vader/analyze", json=chain()[0].model_dump(mode="json"))
        assert response.status_code == 200
        assert response.json()["findings"][0]["rule_code"] == "EXCESSIVE_LOGIN_FAILURES"
        assert 0 <= response.json()["risk"]["risk_score"] <= 100
        assert client.post("/api/v1/vader/analyze", json={}).status_code == 422


@pytest.mark.parametrize("environment,host", [("production", "127.0.0.1"), ("", "127.0.0.1"),
                                                ("development", "203.0.113.1"), ("development", "testclient")])
def test_api_guard(monkeypatch, environment, host):
    monkeypatch.setenv("VADER_ENV", environment)
    with TestClient(create_app(), client=(host, 12345)) as client:
        assert client.post("/api/v1/vader/analyze", json=event().model_dump(mode="json"),
                           headers={"X-Forwarded-For": "127.0.0.1"}).status_code == 403
