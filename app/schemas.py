"""Validated data contracts for the API and internal incident record."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class AlertInput(BaseModel):
    """Small vendor-neutral alert schema accepted by the ingestion API."""

    source: str = Field(default="Generic SIEM", min_length=1, max_length=100)
    external_id: str = Field(default_factory=lambda: f"ext-{int(datetime.now(timezone.utc).timestamp())}", min_length=1, max_length=160)
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=5000)
    severity: Severity = Severity.MEDIUM
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    entities: dict[str, str] = Field(default_factory=dict)
    raw_event: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=25)

    source_file: str | None = Field(default=None, max_length=255)

    @model_validator(mode="before")
    @classmethod
    def preprocess_raw_dict(cls, data: Any) -> Any:
        if isinstance(data, dict):
            title = data.get("title") or data.get("name") or data.get("alert_name") or data.get("rule_name") or data.get("summary") or "Security Alert Observed"
            description = data.get("description") or data.get("details") or data.get("message") or data.get("reason") or data.get("title") or "No detailed description provided."
            source = data.get("source") or data.get("vendor") or data.get("provider") or data.get("system") or "SIEM Data Feed"
            external_id = str(data.get("external_id") or data.get("id") or data.get("alert_id") or data.get("event_id") or f"evt-{int(datetime.now(timezone.utc).timestamp())}")
            source_file = data.get("source_file") or data.get("_source_file") or data.get("file_name")
            
            data["title"] = str(title)[:290]
            data["description"] = str(description)[:4900]
            data["source"] = str(source)[:95]
            data["external_id"] = str(external_id)[:150]
            if source_file:
                data["source_file"] = str(source_file)[:250]

            sev = str(data.get("severity") or "medium").lower()
            if "crit" in sev:
                data["severity"] = "critical"
            elif "high" in sev:
                data["severity"] = "high"
            elif "low" in sev or "info" in sev:
                data["severity"] = "low"
            else:
                data["severity"] = "medium"

        return data

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class AttackTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    reason: str
    confidence: int = Field(ge=0, le=100)


class Indicator(BaseModel):
    indicator_type: str
    value: str
    source: str


class EnrichmentResult(BaseModel):
    indicator_type: str
    value: str
    classification: str
    summary: str
    provider: str
    malicious_votes: int | None = None
    suspicious_votes: int | None = None
    country: str | None = None
    asn: str | None = None
    reputation_score: int | None = None
    threat_category: str | None = None
    first_seen: str | None = None
    reports_count: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class IOCSearchMatch(BaseModel):
    incident_id: str
    incident_title: str
    severity: Severity
    status: IncidentStatus
    source: str
    created_at: datetime
    match_field: str


class IOCSearchResponse(BaseModel):
    query: str
    indicator_type: str
    total_matches: int
    enrichment: EnrichmentResult | None = None
    matches: list[IOCSearchMatch] = Field(default_factory=list)


class ThreatIntelSummary(BaseModel):
    total_iocs: int
    malicious_iocs: int
    suspicious_iocs: int
    clean_iocs: int
    top_ips: list[dict[str, Any]] = Field(default_factory=list)
    top_domains: list[dict[str, Any]] = Field(default_factory=list)
    top_hashes: list[dict[str, Any]] = Field(default_factory=list)
    recent_enrichments: list[EnrichmentResult] = Field(default_factory=list)


class Assessment(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    priority: Severity
    confidence: int = Field(ge=0, le=100)
    summary: str
    indicators: list[Indicator] = Field(default_factory=list)
    mitre_techniques: list[AttackTechnique] = Field(default_factory=list)
    enrichment: list[EnrichmentResult] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class AuditEventType(str, Enum):
    ALERT_INGESTED = "alert_ingested"
    STATUS_CHANGED = "status_changed"
    ACTION_TAKEN = "action_taken"
    ANALYST_NOTE_ADDED = "analyst_note_added"
    COPILOT_QUERIED = "copilot_queried"


class AuditEvent(BaseModel):
    id: str
    incident_id: str
    event_type: AuditEventType
    summary: str
    details: str = ""
    actor: str = "analyst"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class Incident(BaseModel):
    id: str
    status: IncidentStatus = IncidentStatus.NEW
    created_at: datetime
    updated_at: datetime
    alert: AlertInput
    assessment: Assessment
    actions: list[str] = Field(default_factory=list)
    analyst_notes: str | None = None
    audit_logs: list[AuditEvent] = Field(default_factory=list)


class StatusUpdate(BaseModel):
    status: IncidentStatus


class ActionsUpdate(BaseModel):
    actions: list[str]


class NotesUpdate(BaseModel):
    notes: str = Field(max_length=10000)


class CopilotRequest(BaseModel):
    question: str | None = Field(default=None, max_length=1200)


class CopilotResponse(BaseModel):
    answer: str
    provider: str


class ContainmentTask(BaseModel):
    id: str
    target: str
    action: str
    category: str  # host, user, network, artifact
    status: str = "pending"  # pending, completed, skipped
    reason: str


class ContainmentPlanResponse(BaseModel):
    incident_id: str
    summary: str
    tasks: list[ContainmentTask]
    provider: str


class RootCauseAnalysis(BaseModel):
    incident_id: str
    attack_vector: str
    compromise_scope: str
    attacker_intent: str
    root_cause_summary: str
    recommended_remediation: list[str]
    provider: str


class ExecutiveSummaryResponse(BaseModel):
    incident_id: str
    title: str
    executive_summary: str
    business_impact: str
    status_verdict: str
    key_recommendations: list[str]
    provider: str


class MitreMatrixTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    hit_count: int
    incident_ids: list[str] = Field(default_factory=list)


class MitreTacticGroup(BaseModel):
    tactic_name: str
    total_hits: int
    techniques: list[MitreMatrixTechnique] = Field(default_factory=list)


class MitreMatrixResponse(BaseModel):
    total_techniques_mapped: int
    total_technique_hits: int
    tactics: list[MitreTacticGroup] = Field(default_factory=list)


class SOARScript(BaseModel):
    language: str
    title: str
    description: str
    code: str


class SOARPlaybookResponse(BaseModel):
    incident_id: str
    target_entities: list[str] = Field(default_factory=list)
    scripts: list[SOARScript] = Field(default_factory=list)




