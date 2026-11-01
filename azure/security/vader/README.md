# VADER Phase 1

VADER (Virtual Autonomous Defense, Evaluation & Response) is MESH's security
intelligence engine. Phase 1 evaluates synthetic signals locally, without cloud
connections, database writes, credentials, or automated response actions.

## Architecture

`models/security_event.py` validates tenant-scoped events with Pydantic v2.
`detectors/rules.py` applies independent deterministic rules.
`correlation/engine.py` groups events by organization and actor, removes identical
events, sorts timestamps, and matches ordered chains. `risk/engine.py` explains
heuristic scores. `main.py` exposes a local FastAPI service with typed responses.

Event types are `login`, `privilege_escalation`, `sensitive_resource_access`, and
`data_transfer`. Timestamps must be timezone aware and are normalized to UTC;
omitted timestamps use current UTC. IP addresses are validated. Counts must be
nonnegative integers (booleans, strings and fractional counts are rejected).
Authorization must be an actual boolean. Login details default to zero failures;
authorization and transfer events require their relevant detail field. Extra
detail metadata is preserved for future signal adapters.

## Detection rules

| Code | Trigger | Severity |
| --- | --- | --- |
| EXCESSIVE_LOGIN_FAILURES | failed_attempts >= 5 | high |
| UNAUTHORIZED_PRIVILEGE_ESCALATION | authorized is false | critical |
| UNAUTHORIZED_SENSITIVE_ACCESS | authorized is false | critical |
| LARGE_DATA_TRANSFER | bytes_transferred >= 1,000,000,000 | high |

These thresholds are demonstration defaults, not production security guarantees.
A large transfer is a volume signal and does not establish malicious activity.

## Correlation

Call `correlate_events(events, window=timedelta(minutes=60))` with validated
events. Only the sequence suspicious login → unauthorized escalation →
unauthorized sensitive access → large transfer matches. Each stage must occur
strictly after the previous one, and the entire chain must fit the window
(inclusive boundary). Input order does not matter; actual timestamps determine
order. Neither tenant nor identity boundaries can be crossed. Benign or unrelated
events cannot advance a chain.

For each terminal transfer the engine selects the most recent compatible chain.
Exact duplicate events and identical sequences are deduplicated; overlapping
chains with different terminal transfers remain separate candidate results.
Results include a stable sequence fingerprint, matched events, rule findings,
time range and evidence. Identity, time and the full rule sequence provide the
association; Phase 1 cannot prove causation or identify shared sessions/resources.
Matches are candidate attack chains, never confirmed attacks. State is per call,
with no persistent incident deduplication or storage. Very large batches should
be bounded by future ingestion adapters.

## Risk methodology

Score = min(100, round(maximum severity weight + behavior points + chain bonus
+ evidence points)). High severity weighs 30; critical weighs 45; no findings
weigh zero. Each distinct rule contributes 5 points, capped at 20. A supplied
chain contributes 25 when findings exist. Evidence contributes up to 10 points:
the average fraction of three available fields per finding (rule-specific
measurement/authorization, timestamp, and source IP). Confidence is that same
fraction, from 0 to 1, rounded to three decimals. Missing IP reduces completeness.
Levels: low <30, medium 30–59, high 60–79, critical >=80.

This deterministic heuristic uses no LLM. Confidence measures completeness only;
it is not a probability of compromise or verification that input is truthful.
Severity, thresholds and weights require calibration against real workloads.
The scoring function expects findings and chains from the same analysis scope;
callers must supply corresponding correlation results. The single-event API has
no chain bonus because it has no event history.

## Windows development

From the repository root, activate the existing environment:

```powershell
.\azure\security\vader\.venv\Scripts\Activate.ps1
python -m pytest azure/security/vader/tests -q
$env:VADER_ENV = 'development'
python -m uvicorn azure.security.vader.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Activation is optional; the explicit test command is:

```powershell
.\azure\security\vader\.venv\Scripts\python.exe -m pytest azure/security/vader/tests -q
```

`GET /` describes the service; `GET /health` returns `{"status":"ok"}`.
`POST /api/v1/vader/analyze` accepts one synthetic event and returns findings and
risk. Analysis is disabled unless `VADER_ENV=development` at app creation and the
direct peer address is loopback. Other callers receive 403. Interactive docs are
enabled only in development. Never publish this development service, bind to a
public interface, or put it behind a public reverse proxy/tunnel. The loopback
check cannot distinguish a local proxy from a local user. Disable proxy-header
trust with the provided command. Production integration requires authentication,
tenant authorization, rate limits and an approved deployment design.

Example synthetic request:

```powershell
$body = @{
  organization_id = '11111111-1111-1111-1111-111111111111'
  event_type = 'login'
  actor_identifier = 'synthetic-user'
  event_time = '2026-01-01T00:00:00Z'
  source_ip = '192.0.2.10'
  details = @{ failed_attempts = 5 }
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/v1/vader/analyze' -ContentType 'application/json' -Body $body
```

Expected: one `EXCESSIVE_LOGIN_FAILURES` finding with high severity, explanation,
evidence, organization and actor; risk score 45, medium risk level, contributing
factors 30 + 5 + 0 + 10, and confidence estimate 1.0. A normal login returns no
findings and risk score zero. Invalid events return 422.

## Limitations and next milestone

All signals are caller supplied; no source verification, baseline learning,
cross-request correlation, persistence or remediation exists. Local access is
not production authentication. RLS, migrations and the remote Supabase project
are untouched. Reconcile the local migration history with the existing remote
schema next, then design authenticated tenant-scoped ingestion and persistence
for security events, findings, incidents and risk scores. Azure/AWS/GitHub/IAM
and DevTrack adapters can then normalize signals into this model. Add production
authorization and operational controls before any network deployment.
