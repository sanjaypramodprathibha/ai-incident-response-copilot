"""Deterministic incident triage logic.

Keeping a transparent baseline means analysts can review why a case was scored
before enabling any optional model-generated explanation.
"""

from __future__ import annotations

import json

from app.schemas import AlertInput, Assessment, Severity
from app.services.mitre import map_to_mitre
from app.services.threat_intel import ThreatIntelEnricher, extract_indicators


SEVERITY_BASE: dict[Severity, int] = {
    Severity.LOW: 18,
    Severity.MEDIUM: 42,
    Severity.HIGH: 65,
    Severity.CRITICAL: 84,
}


def _priority(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 35:
        return Severity.MEDIUM
    return Severity.LOW


def _recommendations(alert: AlertInput, technique_ids: set[str], risk_score: int) -> list[str]:
    actions = ["Validate the alert against source telemetry and establish the affected user, host, and time window."]
    if {"T1110", "T1078"} & technique_ids:
        actions.extend(
            [
                "Review sign-in history, MFA prompts, and conditional-access results for the affected identity.",
                "If compromise is confirmed, revoke active sessions and reset credentials through the approved response process.",
            ]
        )
    if {"T1059.001", "T1059.003", "T1105"} & technique_ids:
        actions.extend(
            [
                "Preserve process, command-line, parent-process, and network telemetry from the affected host.",
                "Compare the activity with approved administration and software-deployment records before containment.",
            ]
        )
    if "T1566" in technique_ids:
        actions.extend(
            [
                "Review the message, sender authentication, URL clicks, and mailbox rules in an isolated investigation workflow.",
                "Search for matching messages or indicators across the mail environment.",
            ]
        )
    if risk_score >= 80:
        actions.append("Escalate to the incident commander or on-call security lead according to the response runbook.")
    actions.append("Document evidence, decisions, and any approved response actions in the case record.")
    # Preserve order while avoiding repeated advice when multiple rules apply.
    return list(dict.fromkeys(actions))


class IncidentAnalyzer:
    def __init__(self, enricher: ThreatIntelEnricher | None = None) -> None:
        self.enricher = enricher or ThreatIntelEnricher()

    async def analyze(self, alert: AlertInput) -> Assessment:
        context = " ".join(
            [
                alert.title,
                alert.description,
                " ".join(alert.tags),
                json.dumps(alert.entities, sort_keys=True),
                json.dumps(alert.raw_event, sort_keys=True, default=str),
            ]
        )
        indicators = extract_indicators(context)
        techniques = map_to_mitre(context)
        enrichment = await self.enricher.enrich_all(indicators)

        score = SEVERITY_BASE[alert.severity]
        score += min(12, len(indicators) * 3)
        score += min(14, len(techniques) * 5)
        score += sum(10 for item in enrichment if item.classification == "malicious")
        score += sum(4 for item in enrichment if item.classification == "suspicious")
        score = min(100, score)
        confidence = min(96, 45 + len(techniques) * 11 + len(indicators) * 4)
        technique_ids = {item.technique_id for item in techniques}
        summary = (
            f"{alert.severity.value.title()} alert from {alert.source} scored {score}/100. "
            f"Observed {len(indicators)} indicator(s) and mapped {len(techniques)} ATT&CK technique(s)."
        )
        return Assessment(
            risk_score=score,
            priority=_priority(score),
            confidence=confidence,
            summary=summary,
            indicators=indicators,
            mitre_techniques=techniques,
            enrichment=enrichment,
            recommended_actions=_recommendations(alert, technique_ids, score),
        )

