"""Deterministic demonstration rules; matches are signals, not verdicts."""
from dataclasses import dataclass
from typing import Literal
from pydantic import BaseModel
from ..models.security_event import SecurityEvent


class Finding(BaseModel):
    rule_code: str
    severity: Literal["high", "critical"]
    explanation: str
    evidence: dict
    organization_id: str
    actor_identifier: str


@dataclass(frozen=True)
class Rule:
    event_type: str
    code: str
    severity: str
    field: str
    threshold: int | bool
    explanation: str

    def matches(self, event: SecurityEvent) -> bool:
        value = event.details.get(self.field)
        return event.event_type == self.event_type and (
            value is False if self.threshold is False else value is not None and value >= self.threshold
        )


RULES = (
    Rule("login", "EXCESSIVE_LOGIN_FAILURES", "high", "failed_attempts", 5, "At least five failed login attempts were reported."),
    Rule("privilege_escalation", "UNAUTHORIZED_PRIVILEGE_ESCALATION", "critical", "authorized", False, "Privilege escalation was reported as unauthorized."),
    Rule("sensitive_resource_access", "UNAUTHORIZED_SENSITIVE_ACCESS", "critical", "authorized", False, "Sensitive resource access was reported as unauthorized."),
    Rule("data_transfer", "LARGE_DATA_TRANSFER", "high", "bytes_transferred", 1_000_000_000, "Transfer meets the demonstration volume threshold; malicious activity is not confirmed."),
)


def detect_threats(event: SecurityEvent) -> list[dict]:
    return [Finding(rule_code=r.code, severity=r.severity, explanation=r.explanation,
                    evidence={r.field: event.details[r.field], "event_time": event.event_time.isoformat(),
                              "source_ip": str(event.source_ip) if event.source_ip else None},
                    organization_id=str(event.organization_id), actor_identifier=event.actor_identifier).model_dump()
            for r in RULES if r.matches(event)]
