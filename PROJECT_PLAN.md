# AI Incident Response Copilot — project plan

## Goal

Build a safe, portfolio-ready application that turns SIEM-style alerts into a structured incident investigation. It assists with triage and reporting; it does not execute containment actions.

## Delivered scope

1. **Ingestion** — REST endpoints, a dashboard form, JSON batch import, and bundled sample alerts.
2. **Triage** — severity-aware risk scoring, indicator extraction, investigation recommendations, and a persistent local SQLite case store.
3. **MITRE ATT&CK mapping** — transparent keyword rules map alert context to techniques and include the reason for each match.
4. **Threat intelligence** — offline IOC context works immediately; optional VirusTotal enrichment activates only when its API key is configured.
5. **Copilot** — deterministic analyst narrative and Q&A work without credentials; an optional OpenAI Responses API path produces contextual narratives when configured.
6. **Reporting** — download each case as Markdown or PDF.
7. **Verification** — focused unit tests cover indicator extraction, ATT&CK mapping, scoring, and report content.

## Architecture

```text
SIEM / JSON alert
       |
FastAPI ingestion API ──> Triage service ──> ATT&CK mapper
       |                       |                   |
       |                       v                   v
       +----------------> IOC enrichment <── optional VirusTotal
       |
SQLite case store <── Dashboard / Copilot / Markdown or PDF report
                              |
                     optional OpenAI narrative
```

## Build milestones

| Milestone | Outcome | Status |
| --- | --- | --- |
| M1 | Define alert, IOC, incident, and API models | Complete |
| M2 | Implement ingestion, scoring, ATT&CK, and local enrichment | Complete |
| M3 | Add browser dashboard and incident detail workflow | Complete |
| M4 | Add optional external enrichment and AI narrative provider | Complete |
| M5 | Add reports, tests, setup documentation, and container support | Complete |

## Suggested next iterations

- Replace keyword mapping with a versioned ATT&CK knowledge base and detection-specific rules.
- Add authentication, RBAC, audit logs, case collaboration, and a production database before deploying.
- Build a real connector for Sentinel, Splunk, or Elastic using least-privileged read-only credentials.
- Add test fixtures from an approved lab environment and evaluation cases for the model output.

