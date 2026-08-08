"""A compact SQLite case store, suitable for a local demo and test runs."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.schemas import (
    AlertInput,
    Assessment,
    AuditEvent,
    AuditEventType,
    EnrichmentResult,
    IOCSearchMatch,
    IOCSearchResponse,
    Incident,
    IncidentStatus,
    MitreMatrixResponse,
    MitreMatrixTechnique,
    MitreTacticGroup,
    ThreatIntelSummary,
)


from app.services.mitre import map_to_mitre


def _ensure_mitre(inc: Incident) -> Incident:
    if not inc.assessment.mitre_techniques:
        context = " ".join([inc.alert.title, inc.alert.description, " ".join(inc.alert.tags), inc.alert.source])
        techs = map_to_mitre(context)
        if techs:
            inc.assessment.mitre_techniques = techs
    return inc


class CaseStore:
    def __init__(self, database_path: Path) -> None:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self.database_path = database_path
        self._lock = threading.Lock()
        self._initialize()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    details TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                )"""
            )

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def add_audit_event(
        self,
        incident_id: str,
        event_type: AuditEventType,
        summary: str,
        details: str = "",
        actor: str = "analyst",
    ) -> AuditEvent:
        now = self._now()
        event = AuditEvent(
            id=str(uuid4()),
            incident_id=incident_id,
            event_type=event_type,
            summary=summary,
            details=details,
            actor=actor,
            timestamp=now,
        )
        with self._lock, self._connection() as connection:
            connection.execute(
                """INSERT INTO audit_logs (id, incident_id, event_type, summary, details, actor, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.id,
                    event.incident_id,
                    event.event_type.value,
                    event.summary,
                    event.details,
                    event.actor,
                    now.isoformat(),
                ),
            )
        return event

    def get_audit_logs(self, incident_id: str) -> list[AuditEvent]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_logs WHERE incident_id = ? ORDER BY timestamp ASC",
                (incident_id,),
            ).fetchall()
        return [
            AuditEvent(
                id=row["id"],
                incident_id=row["incident_id"],
                event_type=AuditEventType(row["event_type"]),
                summary=row["summary"],
                details=row["details"],
                actor=row["actor"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
            )
            for row in rows
        ]

    def create(self, alert: AlertInput, assessment: Assessment) -> Incident:
        now = self._now()
        incident_id = str(uuid4())
        initial_event = AuditEvent(
            id=str(uuid4()),
            incident_id=incident_id,
            event_type=AuditEventType.ALERT_INGESTED,
            summary=f"Alert '{alert.title}' ingested from {alert.source}",
            details=f"Initial risk score: {assessment.risk_score}/100. Priority: {assessment.priority.value.upper()}.",
            actor="system",
            timestamp=now,
        )
        incident = Incident(
            id=incident_id,
            created_at=now,
            updated_at=now,
            alert=alert,
            assessment=assessment,
            audit_logs=[initial_event],
        )
        payload = incident.model_dump_json()
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO incidents (id, status, created_at, updated_at, payload) VALUES (?, ?, ?, ?, ?)",
                (incident.id, incident.status.value, now.isoformat(), now.isoformat(), payload),
            )
            connection.execute(
                """INSERT INTO audit_logs (id, incident_id, event_type, summary, details, actor, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    initial_event.id,
                    initial_event.incident_id,
                    initial_event.event_type.value,
                    initial_event.summary,
                    initial_event.details,
                    initial_event.actor,
                    now.isoformat(),
                ),
            )
        return incident

    def list(self) -> list[Incident]:
        with self._connection() as connection:
            rows = connection.execute("SELECT payload FROM incidents ORDER BY created_at DESC").fetchall()
        incidents = []
        for row in rows:
            inc = Incident.model_validate_json(row["payload"])
            inc.audit_logs = self.get_audit_logs(inc.id)
            incidents.append(_ensure_mitre(inc))
        return incidents

    def get(self, incident_id: str) -> Incident | None:
        with self._connection() as connection:
            row = connection.execute("SELECT payload FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not row:
            return None
        incident = Incident.model_validate_json(row["payload"])
        incident.audit_logs = self.get_audit_logs(incident_id)
        return _ensure_mitre(incident)

    def update_status(self, incident_id: str, status: IncidentStatus) -> Incident | None:
        with self._lock:
            incident = self.get(incident_id)
            if not incident:
                return None
            old_status = incident.status.value
            updated = incident.model_copy(update={"status": status, "updated_at": self._now()})
            with self._connection() as connection:
                connection.execute(
                    "UPDATE incidents SET status = ?, updated_at = ?, payload = ? WHERE id = ?",
                    (updated.status.value, updated.updated_at.isoformat(), updated.model_dump_json(), incident_id),
                )
        self.add_audit_event(
            incident_id=incident_id,
            event_type=AuditEventType.STATUS_CHANGED,
            summary=f"Incident status updated from {old_status.upper()} to {status.value.upper()}",
            details=f"Status set to {status.value}.",
            actor="analyst",
        )
        return self.get(incident_id)

    def update_actions(self, incident_id: str, actions: list[str]) -> Incident | None:
        with self._lock:
            incident = self.get(incident_id)
            if not incident:
                return None
            updated = incident.model_copy(
                update={
                    "actions": actions,
                    "updated_at": self._now(),
                }
            )
            with self._connection() as connection:
                connection.execute(
                    """
                    UPDATE incidents
                    SET updated_at = ?, payload = ?
                    WHERE id = ?
                    """,
                    (
                        updated.updated_at.isoformat(),
                        updated.model_dump_json(),
                        incident_id,
                    ),
                )
        new_actions_summary = ", ".join(actions) if actions else "No actions checked"
        self.add_audit_event(
            incident_id=incident_id,
            event_type=AuditEventType.ACTION_TAKEN,
            summary=f"Analyst updated response actions: {new_actions_summary}",
            details=f"Active actions: {new_actions_summary}",
            actor="analyst",
        )
        return self.get(incident_id)

    def update_notes(self, incident_id: str, notes: str) -> Incident | None:
        with self._lock:
            incident = self.get(incident_id)
            if not incident:
                return None
            updated = incident.model_copy(
                update={
                    "analyst_notes": notes,
                    "updated_at": self._now(),
                }
            )
            with self._connection() as connection:
                connection.execute(
                    """
                    UPDATE incidents
                    SET updated_at = ?, payload = ?
                    WHERE id = ?
                    """,
                    (
                        updated.updated_at.isoformat(),
                        updated.model_dump_json(),
                        incident_id,
                    ),
                )
        note_snippet = notes[:80] + "..." if len(notes) > 80 else notes
        self.add_audit_event(
            incident_id=incident_id,
            event_type=AuditEventType.ANALYST_NOTE_ADDED,
            summary=f"Analyst added investigation notes",
            details=note_snippet,
            actor="analyst",
        )
        return self.get(incident_id)

    def search_iocs(self, query: str) -> IOCSearchResponse:
        q = query.strip().lower()
        if not q:
            return IOCSearchResponse(query="", indicator_type="unknown", total_matches=0)

        # Detect indicator type heuristically
        if "." in q and not any(c in q for c in ["/", " ", ":"]):
            if q.replace(".", "").isdigit():
                indicator_type = "ip"
            else:
                indicator_type = "domain"
        elif len(q) == 64 and all(c in "0123456789abcdef" for c in q):
            indicator_type = "sha256"
        elif q.startswith("http://") or q.startswith("https://"):
            indicator_type = "url"
        else:
            indicator_type = "keyword"

        incidents = self.list()
        matches: list[IOCSearchMatch] = []
        matching_enrichment: EnrichmentResult | None = None

        for inc in incidents:
            matched_fields = []
            # Check extracted indicators
            for ind in inc.assessment.indicators:
                if q in ind.value.lower():
                    matched_fields.append(f"Indicator ({ind.indicator_type})")
            # Check enrichment results
            for enr in inc.assessment.enrichment:
                if q in enr.value.lower():
                    matched_fields.append(f"Enrichment ({enr.provider})")
                    if not matching_enrichment:
                        matching_enrichment = enr
            # Check alert text
            if q in inc.alert.title.lower():
                matched_fields.append("Alert Title")
            if q in inc.alert.description.lower():
                matched_fields.append("Alert Description")
            if q in json.dumps(inc.alert.entities).lower():
                matched_fields.append("Alert Entities")

            if matched_fields:
                matches.append(
                    IOCSearchMatch(
                        incident_id=inc.id,
                        incident_title=inc.alert.title,
                        severity=inc.assessment.priority,
                        status=inc.status,
                        source=inc.alert.source,
                        created_at=inc.created_at,
                        match_field=", ".join(set(matched_fields)),
                    )
                )

        return IOCSearchResponse(
            query=query,
            indicator_type=indicator_type,
            total_matches=len(matches),
            enrichment=matching_enrichment,
            matches=matches,
        )

    def get_threat_intel_summary(self) -> ThreatIntelSummary:
        incidents = self.list()
        all_enrichments: list[EnrichmentResult] = []
        ip_counts: dict[str, int] = {}
        domain_counts: dict[str, int] = {}
        hash_counts: dict[str, int] = {}

        malicious_count = 0
        suspicious_count = 0
        clean_count = 0

        for inc in incidents:
            for ind in inc.assessment.indicators:
                val = ind.value
                if ind.indicator_type == "ip":
                    ip_counts[val] = ip_counts.get(val, 0) + 1
                elif ind.indicator_type == "domain":
                    domain_counts[val] = domain_counts.get(val, 0) + 1
                elif ind.indicator_type == "sha256":
                    hash_counts[val] = hash_counts.get(val, 0) + 1

            for enr in inc.assessment.enrichment:
                all_enrichments.append(enr)
                if enr.classification == "malicious":
                    malicious_count += 1
                elif enr.classification in {"suspicious", "unknown"}:
                    suspicious_count += 1
                else:
                    clean_count += 1

        top_ips = [{"value": ip, "count": cnt} for ip, cnt in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
        top_domains = [{"value": dom, "count": cnt} for dom, cnt in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
        top_hashes = [{"value": h, "count": cnt} for h, cnt in sorted(hash_counts.items(), key=lambda x: x[1], reverse=True)[:5]]

        return ThreatIntelSummary(
            total_iocs=len(all_enrichments),
            malicious_iocs=malicious_count,
            suspicious_iocs=suspicious_count,
            clean_iocs=clean_count,
            top_ips=top_ips,
            top_domains=top_domains,
            top_hashes=top_hashes,
            recent_enrichments=all_enrichments[:10],
        )

    def get_mitre_matrix(self) -> MitreMatrixResponse:
        incidents = self.list()
        tactic_map: dict[str, dict[str, MitreMatrixTechnique]] = {}
        total_hits = 0

        for inc in incidents:
            for tech in inc.assessment.mitre_techniques:
                tactic = tech.tactic or "Execution"
                if tactic not in tactic_map:
                    tactic_map[tactic] = {}

                if tech.technique_id not in tactic_map[tactic]:
                    tactic_map[tactic][tech.technique_id] = MitreMatrixTechnique(
                        technique_id=tech.technique_id,
                        name=tech.name,
                        tactic=tactic,
                        hit_count=0,
                        incident_ids=[]
                    )

                item = tactic_map[tactic][tech.technique_id]
                item.hit_count += 1
                if inc.id not in item.incident_ids:
                    item.incident_ids.append(inc.id)
                total_hits += 1

        standard_tactics = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact"
        ]

        all_tactics = list(dict.fromkeys([t for t in standard_tactics if t in tactic_map] + list(tactic_map.keys()) + standard_tactics))
        tactic_groups: list[MitreTacticGroup] = []

        for tactic in all_tactics:
            techs = list(tactic_map.get(tactic, {}).values())
            sum_hits = sum(t.hit_count for t in techs)
            tactic_groups.append(MitreTacticGroup(
                tactic_name=tactic,
                total_hits=sum_hits,
                techniques=sorted(techs, key=lambda x: x.hit_count, reverse=True)
            ))

        total_mapped = sum(len(group.techniques) for group in tactic_groups)

        return MitreMatrixResponse(
            total_techniques_mapped=total_mapped,
            total_technique_hits=total_hits,
            tactics=tactic_groups
        )

    def get_source_files_summary(self) -> list[dict[str, Any]]:
        with self._lock, self._connection() as connection:
            rows = connection.execute("SELECT payload FROM incidents").fetchall()
            files_map: dict[str, dict[str, Any]] = {}
            for row in rows:
                payload = json.loads(row["payload"])
                alert = payload.get("alert", {})
                source_file = alert.get("source_file") or alert.get("raw_event", {}).get("_source_file") or "Manual / Direct Ingestion"
                source = alert.get("source", "SIEM Feed")
                sev = str(alert.get("severity", "medium")).lower()

                if source_file not in files_map:
                    files_map[source_file] = {
                        "source_file": source_file,
                        "source": source,
                        "incident_count": 0,
                        "sample_titles": [],
                        "priorities": {"critical": 0, "high": 0, "medium": 0, "low": 0}
                    }
                
                entry = files_map[source_file]
                entry["incident_count"] += 1
                if sev in entry["priorities"]:
                    entry["priorities"][sev] += 1
                if len(entry["sample_titles"]) < 3 and alert.get("title"):
                    entry["sample_titles"].append(alert.get("title"))

            return list(files_map.values())

    def delete_by_source_file(self, source_file: str) -> int:
        with self._lock, self._connection() as connection:
            rows = connection.execute("SELECT id, payload FROM incidents").fetchall()
            ids_to_delete = []
            for row in rows:
                payload = json.loads(row["payload"])
                alert = payload.get("alert", {})
                f_name = alert.get("source_file") or alert.get("raw_event", {}).get("_source_file") or "Manual / Direct Ingestion"
                if f_name == source_file:
                    ids_to_delete.append(row["id"])
            
            for inc_id in ids_to_delete:
                connection.execute("DELETE FROM audit_logs WHERE incident_id = ?", (inc_id,))
                connection.execute("DELETE FROM incidents WHERE id = ?", (inc_id,))
            
            return len(ids_to_delete)

    def delete_incident(self, incident_id: str) -> bool:
        with self._lock, self._connection() as connection:
            connection.execute("DELETE FROM audit_logs WHERE incident_id = ?", (incident_id,))
            cursor = connection.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
            return cursor.rowcount > 0

    def clear(self) -> None:
        with self._lock, self._connection() as connection:
            connection.execute("DELETE FROM audit_logs")
            connection.execute("DELETE FROM incidents")



