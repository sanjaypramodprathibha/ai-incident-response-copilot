"""Analyst-facing narrative provider with a reliable local fallback."""

from __future__ import annotations

import json
import os
from typing import Any
from google import genai
from app.schemas import (
    ContainmentPlanResponse,
    ContainmentTask,
    ExecutiveSummaryResponse,
    Incident,
    RootCauseAnalysis,
)
import time
import random


STRUCTURED_ASSESSMENT_INSTRUCTIONS = """
You are an expert Incident Response Copilot for a defensive Security Operations Center (SOC).

Generate a full structured assessment report formatted strictly into these 4 sections:

## Assessment

A short analyst summary of the alert risk score, confidence level, and source telemetry.

## Evidence

- Bullet points detailing mapped MITRE ATT&CK techniques, indicators of compromise (IOCs), and target entities.

## Investigation Steps

1. Numbered, step-by-step investigation and verification actions.

## Escalation Note

A short recommendation on containment thresholds and escalation criteria.

Rules:
- Strictly follow the 4 section headers above.
- Never invent facts not present in the incident data.
- Maintain a professional, authoritative SOC tone.
"""

GENERAL_QA_INSTRUCTIONS = """
You are an expert Incident Response Copilot for a defensive Security Operations Center (SOC).

Directly and concisely answer the analyst's specific question or request using only the provided incident data.

Rules:
- Answer ONLY the specific question asked in a clean, natural Markdown format.
- Do NOT output boilerplate templates or fixed multi-section reports unless explicitly requested.
- Use clean Markdown formatting (bold text, bullet points, or numbered lists) appropriate to answer the question clearly.
- Maintain a professional, concise, and helpful tone for SOC analysts.
"""


def _local_answer(incident: Incident, question: str | None) -> str:
    assessment = incident.assessment
    techniques = ", ".join(f"{t.technique_id} ({t.name})" for t in assessment.mitre_techniques) or "No ATT&CK rule matched"
    indicators = ", ".join(f"{item.indicator_type}: {item.value}" for item in assessment.indicators) or "No IOCs extracted"
    actions = "\n".join(f"1. {action}" for action in assessment.recommended_actions)
    
    is_structured = not question or any(k in (question or "").lower() for k in ["full assessment", "structured assessment", "initial assessment", "full report"])

    if is_structured:
        return f"""## Assessment
{assessment.summary} Risk Score: **{assessment.risk_score}/100** | Analyst Confidence: **{assessment.confidence}%** | Case Status: **{incident.status.value.upper()}**

## Evidence
- **Alert Source**: {incident.alert.source} (External ID: `{incident.alert.external_id}`)
- **Mapped MITRE ATT&CK**: {techniques}
- **Indicators of Compromise**: {indicators}

## Investigation Steps
{actions}

## Escalation Note
Validate source telemetry and blast radius before taking containment actions. Escalate to Tier 2 if active C2 beaconing or credential harvesting is confirmed."""
    else:
        return f"""### Answer: {question}

For incident **{incident.alert.title}** ({incident.alert.source}), review telemetry for target entities, check mapped MITRE techniques ({techniques}), and follow approved SOC runbooks.

**Recommended Actions:**
{actions}"""


class CopilotNarrator:
    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        configured_model = model or os.getenv("GEMINI_MODEL", "gemini-flash-latest")
        if configured_model in {"gemini-2.5-flash", "gemini-3-flash-preview"}:
            configured_model = "gemini-flash-latest"
        self.model = configured_model

    def answer(self, incident: Incident, question: str | None = None) -> tuple[str, str]:
        """Use Gemini when configured; otherwise remain local."""

        if not self.api_key:
            return _local_answer(incident, question), "Offline Analysis"

        is_structured = not question or any(k in (question or "").lower() for k in ["full assessment", "structured assessment", "initial assessment", "full report"])
        sys_instruction = STRUCTURED_ASSESSMENT_INSTRUCTIONS if is_structured else GENERAL_QA_INSTRUCTIONS

        payload: dict[str, Any] = {
            "incident": incident.model_dump(mode="json"),
            "analyst_question": question or "Create the initial incident assessment.",
        }

        client = genai.Client(api_key=self.api_key)
        candidate_models = list(dict.fromkeys([self.model, "gemini-flash-latest", "gemini-flash-lite-latest"]))

        for target_model in candidate_models:
            for attempt in range(2):
                try:
                    response = client.models.generate_content(
                        model=target_model,
                        contents=json.dumps(payload),
                        config={
                            "system_instruction": sys_instruction,
                            "temperature": 0.2,
                        },
                    )

                    answer = ""
                    try:
                        answer = (response.text or "").strip()
                    except Exception:
                        pass

                    if not answer and hasattr(response, "candidates") and response.candidates:
                        parts = []
                        for cand in response.candidates:
                            if hasattr(cand, "content") and hasattr(cand.content, "parts"):
                                for part in cand.content.parts:
                                    if hasattr(part, "text") and part.text:
                                        parts.append(part.text)
                        answer = "".join(parts).strip()

                    if answer:
                        return answer, f"Gemini ({target_model})"

                except Exception as e:
                    print(f"Gemini model {target_model} attempt {attempt + 1} failed: {e}")
                    time.sleep(0.5)

        return (
            _local_answer(incident, question),
            "Offline Analysis",
        )

    def generate_containment_plan(self, incident: Incident) -> ContainmentPlanResponse:
        tasks: list[ContainmentTask] = []
        task_id = 1

        entities = incident.alert.entities or {}
        host = entities.get("host") or entities.get("hostname") or entities.get("computer")
        user = entities.get("user") or entities.get("username") or entities.get("account") or entities.get("mailbox")

        if host:
            tasks.append(ContainmentTask(
                id=f"task-{task_id}",
                target=str(host),
                action=f"Isolate Host '{host}' from Network",
                category="host",
                status="pending",
                reason=f"Prevent potential lateral movement from compromised host '{host}'."
            ))
            task_id += 1

        if user:
            tasks.append(ContainmentTask(
                id=f"task-{task_id}",
                target=str(user),
                action=f"Revoke Active SSO & OAuth Sessions for '{user}'",
                category="user",
                status="pending",
                reason=f"Mitigate identity compromise for account '{user}'."
            ))
            task_id += 1
            tasks.append(ContainmentTask(
                id=f"task-{task_id}",
                target=str(user),
                action=f"Enforce Mandatory Password Reset for '{user}'",
                category="user",
                status="pending",
                reason=f"Ensure credential integrity following suspicious authentication activity."
            ))
            task_id += 1

        for ind in incident.assessment.indicators:
            if ind.indicator_type == "ip":
                tasks.append(ContainmentTask(
                    id=f"task-{task_id}",
                    target=ind.value,
                    action=f"Block C2 IP '{ind.value}' on Perimeter Firewall",
                    category="network",
                    status="pending",
                    reason=f"Deny inbound and outbound communication with observed external IP '{ind.value}'."
                ))
                task_id += 1
            elif ind.indicator_type in {"domain", "url"}:
                tasks.append(ContainmentTask(
                    id=f"task-{task_id}",
                    target=ind.value,
                    action=f"Sinkhole DNS & Add Web Filter Block for '{ind.value}'",
                    category="network",
                    status="pending",
                    reason=f"Prevent internal hosts from accessing malicious domain/URL '{ind.value}'."
                ))
                task_id += 1
            elif ind.indicator_type == "sha256":
                tasks.append(ContainmentTask(
                    id=f"task-{task_id}",
                    target=ind.value,
                    action=f"Add Binary Hash '{ind.value[:12]}...' to EDR Global Quarantine",
                    category="artifact",
                    status="pending",
                    reason=f"Quarantine binary execution matching hash signature."
                ))
                task_id += 1

        if not tasks:
            tasks.append(ContainmentTask(
                id="task-1",
                target=incident.alert.source,
                action="Preserve Process Memory Dump & Endpoint Telemetry",
                category="host",
                status="pending",
                reason="Collect forensic artifacts prior to taking destructive response actions."
            ))

        summary = f"Generated {len(tasks)} containment action items based on observed alert entities and IOCs."
        return ContainmentPlanResponse(
            incident_id=incident.id,
            summary=summary,
            tasks=tasks,
            provider="AI Containment Planner Engine"
        )

    def generate_root_cause(self, incident: Incident) -> RootCauseAnalysis:
        alert = incident.alert
        assessment = incident.assessment

        techniques = [t.name.lower() for t in assessment.mitre_techniques]
        title_lower = alert.title.lower() + " " + alert.description.lower()

        if any("phishing" in t or "email" in t for t in techniques) or "phish" in title_lower or "email" in title_lower:
            vector = "Spearphishing Link / Malicious Email Delivery"
            intent = "Credential Harvesting / Initial Access"
        elif any("powershell" in t or "command" in t for t in techniques) or "powershell" in title_lower:
            vector = "Malicious Script Execution (Encoded PowerShell)"
            intent = "Execution / Defense Evasion / C2 Callback"
        elif any("brute" in t or "credential" in t for t in techniques) or "login" in title_lower or "password" in title_lower:
            vector = "Credential Access / Password Spraying"
            intent = "Account Takeover / Unauthorized Access"
        elif "ransom" in title_lower or "encrypt" in title_lower:
            vector = "Unauthorized Binary Execution (Ransomware Precursor)"
            intent = "Data Encryption / Impact"
        else:
            vector = "Suspicious Telemetry Anomaly"
            intent = "Unverified Suspicious Activity"

        hosts = alert.entities.get("host") or alert.entities.get("hostname") or "Observed Host"
        users = alert.entities.get("user") or alert.entities.get("username") or alert.entities.get("mailbox") or "Observed User"
        scope = f"Host: {hosts} | Identity: {users}"

        summary = f"Root cause assessment indicates a probable {vector} targeting {scope}. Attack intent aligns with {intent}."

        remediations = [
            "Isolate affected endpoints and terminate suspicious child processes.",
            "Revoke compromised session tokens and enforce MFA re-authentication.",
            "Block malicious IOCs at the perimeter firewall and DNS sinkhole.",
            "Review SIEM telemetry for 7 days prior to detect lateral movement."
        ]

        return RootCauseAnalysis(
            incident_id=incident.id,
            attack_vector=vector,
            compromise_scope=scope,
            attacker_intent=intent,
            root_cause_summary=summary,
            recommended_remediation=remediations,
            provider="AI Root Cause Analysis Engine"
        )

    def generate_executive_summary(self, incident: Incident) -> ExecutiveSummaryResponse:
        assessment = incident.assessment
        alert = incident.alert

        time_str = alert.timestamp.strftime('%Y-%m-%d %H:%M UTC') if hasattr(alert.timestamp, 'strftime') else str(alert.timestamp)

        exec_summary = (
            f"On {time_str}, {alert.source} detected a {assessment.priority.value.upper()} risk security incident: '{alert.title}'. "
            f"Risk Score: {assessment.risk_score}/100 with {assessment.confidence}% analyst confidence. "
            f"{assessment.summary}"
        )

        impact = (
            f"Potential business risk to key entities ({', '.join(f'{k}:{v}' for k,v in alert.entities.items()) or 'internal assets'}). "
            f"Observed {len(assessment.indicators)} indicators of compromise and {len(assessment.mitre_techniques)} MITRE ATT&CK techniques."
        )

        verdict = (
            f"ACTIVE INVESTIGATION ({incident.status.value.upper()}) — "
            f"Analyst-in-the-loop triage in progress. Containment playbooks prepared."
        )

        recommendations = [
            "Approve recommended containment playbooks for affected hosts and accounts.",
            "Notify SOC Tier 2 lead and monitor identity provider logs for anomalous access.",
            "Ensure endpoint EDR signatures are updated across the asset group."
        ]

        return ExecutiveSummaryResponse(
            incident_id=incident.id,
            title=alert.title,
            executive_summary=exec_summary,
            business_impact=impact,
            status_verdict=verdict,
            key_recommendations=recommendations,
            provider="AI Executive Summary Engine"
        )