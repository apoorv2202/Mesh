"""Transparent heuristic scoring, never a probability of compromise."""
from pydantic import BaseModel, Field
from ..detectors.rules import Finding


class RiskResult(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    explanation: str
    contributing_factors: dict[str, float]
    confidence_estimate: float = Field(ge=0, le=1)
    confidence_explanation: str


def score_risk(findings: list[dict], attack_chains: list[dict] | None = None) -> RiskResult:
    validated = [Finding.model_validate(f) for f in findings]
    distinct = {f.rule_code for f in validated}
    completeness = (sum(bool(f.evidence.get("event_time")) + bool(f.evidence.get("source_ip"))
                        + any(k in f.evidence for k in ("failed_attempts", "authorized", "bytes_transferred"))
                        for f in validated) / (3 * len(validated))) if validated else 0.0
    factors = {"severity": max((45 if f.severity == "critical" else 30 for f in validated), default=0),
               "distinct_behaviors": min(20, len(distinct) * 5),
               "attack_chain": 25 if attack_chains and validated else 0,
               "evidence_quality": round(10 * completeness, 2)}
    score = min(100, round(sum(factors.values())))
    return RiskResult(risk_score=score, risk_level="critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low",
                      explanation="Maximum severity + distinct behaviors + chain bonus + evidence completeness, capped at 100.",
                      contributing_factors=factors, confidence_estimate=round(completeness, 3),
                      confidence_explanation="Evidence completeness only; not probability of compromise or independently verified truth.")
