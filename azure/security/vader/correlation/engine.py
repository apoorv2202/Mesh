"""Match a strictly ordered four-stage chain within one tenant and identity."""
from collections import defaultdict
from datetime import timedelta
import hashlib
import json
from ..detectors.rules import RULES, detect_threats
from ..models.security_event import SecurityEvent


def correlate_events(events: list[SecurityEvent], window: timedelta = timedelta(minutes=60)) -> list[dict]:
    if window <= timedelta(0):
        raise ValueError("window must be positive")
    groups = defaultdict(dict)
    for event in events:
        key = event.model_dump_json()
        groups[(str(event.organization_id), event.actor_identifier)][key] = event
    results = []
    for (organization, actor), unique in sorted(groups.items()):
        ordered = sorted(unique.values(), key=lambda e: (e.event_time, e.model_dump_json()))
        # Each terminal event selects the most recent compatible predecessors.
        # Unrelated/benign signals never advance the sequence.
        stages = [[] for _ in RULES]
        for event in ordered:
            findings = detect_threats(event)
            if not findings:
                continue
            stage = next(i for i, rule in enumerate(RULES) if rule.code == findings[0]["rule_code"])
            if stage == 0:
                stages[0].append([event])
                continue
            candidates = [chain for chain in stages[stage - 1]
                          if chain[-1].event_time < event.event_time
                          and event.event_time - chain[0].event_time <= window]
            if not candidates:
                continue
            chain = max(candidates, key=lambda c: tuple(e.event_time for e in c)) + [event]
            if stage < 3:
                stages[stage].append(chain)
                continue
            matched = [e.model_dump(mode="json") for e in chain]
            fingerprint = hashlib.sha256(json.dumps(matched, sort_keys=True).encode()).hexdigest()
            results.append({"chain_id": fingerprint, "organization_id": organization, "actor_identifier": actor,
                            "explanation": "Four suspicious behaviors match an ordered chain; compromise is not confirmed.",
                            "matched_events": matched, "detection_rules": [detect_threats(e)[0] for e in chain],
                            "start_time": chain[0].event_time.isoformat(), "end_time": event.event_time.isoformat(),
                            "evidence": {"window_seconds": window.total_seconds(), "strict_order": True}})
    return list({r["chain_id"]: r for r in results}.values())
