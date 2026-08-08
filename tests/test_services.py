import asyncio
from datetime import datetime, timezone

from app.schemas import AlertInput, Severity
from app.services.analyzer import IncidentAnalyzer
from app.services.mitre import map_to_mitre
from app.services.reports import incident_markdown
from app.services.store import CaseStore
from app.services.threat_intel import extract_indicators


def demo_alert() -> AlertInput:
    return AlertInput(
        source="Test SIEM",
        external_id="unit-001",
        title="Encoded PowerShell and failed sign-in activity",
        description="powershell.exe launched with -enc from 10.0.0.12 after a failed sign-in. Destination 198.51.100.10.",
        severity=Severity.HIGH,
        timestamp=datetime(2026, 8, 5, tzinfo=timezone.utc),
    )


def test_extracts_and_deduplicates_indicators():
    indicators = extract_indicators("Contact 198.51.100.10 twice: 198.51.100.10 and https://portal.example.test/a")
    assert [(item.indicator_type, item.value) for item in indicators] == [
        ("ip", "198.51.100.10"),
        ("url", "https://portal.example.test/a"),
    ]


def test_maps_powershell_and_brute_force():
    techniques = map_to_mitre("powershell.exe -enc followed by repeated failed sign-in")
    assert {item.technique_id for item in techniques} >= {"T1059.001", "T1110"}


def test_analyzer_scores_a_high_alert():
    assessment = asyncio.run(IncidentAnalyzer().analyze(demo_alert()))
    assert assessment.risk_score >= 65
    assert assessment.priority in {Severity.HIGH, Severity.CRITICAL}
    assert any(item.technique_id == "T1059.001" for item in assessment.mitre_techniques)


def test_report_contains_case_details(tmp_path):
    alert = demo_alert()
    assessment = asyncio.run(IncidentAnalyzer().analyze(alert))
    incident = CaseStore(tmp_path / "cases.db").create(alert, assessment)
    report = incident_markdown(incident)
    assert incident.id in report
    assert "MITRE ATT&CK mapping" in report
    assert "T1059.001" in report


def test_audit_logs_and_notes(tmp_path):
    from app.schemas import IncidentStatus
    store = CaseStore(tmp_path / "cases.db")
    alert = demo_alert()
    assessment = asyncio.run(IncidentAnalyzer().analyze(alert))
    incident = store.create(alert, assessment)
    
    assert len(incident.audit_logs) == 1
    assert incident.audit_logs[0].event_type == "alert_ingested"

    updated = store.update_status(incident.id, IncidentStatus.INVESTIGATING)
    assert len(updated.audit_logs) == 2
    assert updated.audit_logs[1].event_type == "status_changed"

    updated_notes = store.update_notes(incident.id, "Analyst observed suspicious PowerShell execution")
    assert updated_notes.analyst_notes == "Analyst observed suspicious PowerShell execution"
    assert len(updated_notes.audit_logs) == 3

    report = incident_markdown(updated_notes)
    assert "Analyst notes" in report
    assert "Audit trail & case timeline" in report


def test_delete_single_incident(tmp_path):
    store = CaseStore(tmp_path / "cases.db")
    alert1 = demo_alert()
    alert2 = AlertInput(
        source="Sentinel",
        external_id="unit-002",
        title="Suspicious SSH Login",
        description="SSH login from unknown IP",
        severity=Severity.HIGH,
        timestamp=datetime(2026, 8, 5, tzinfo=timezone.utc),
    )
    inc1 = store.create(alert1, asyncio.run(IncidentAnalyzer().analyze(alert1)))
    inc2 = store.create(alert2, asyncio.run(IncidentAnalyzer().analyze(alert2)))

    assert len(store.list()) == 2
    deleted = store.delete_incident(inc1.id)
    assert deleted is True
    assert len(store.list()) == 1
    assert store.get(inc1.id) is None
    assert store.get(inc2.id) is not None


def test_delete_by_source_file(tmp_path):
    store = CaseStore(tmp_path / "cases.db")
    alert1 = AlertInput(
        source="Sentinel",
        external_id="batch-001",
        title="Alert 1 from Batch A",
        description="Description 1",
        severity=Severity.HIGH,
        source_file="batch_a.json",
    )
    alert2 = AlertInput(
        source="Sentinel",
        external_id="batch-002",
        title="Alert 2 from Batch A",
        description="Description 2",
        severity=Severity.CRITICAL,
        source_file="batch_a.json",
    )
    alert3 = AlertInput(
        source="CrowdStrike",
        external_id="batch-003",
        title="Alert 1 from Batch B",
        description="Description 3",
        severity=Severity.LOW,
        source_file="batch_b.csv",
    )

    store.create(alert1, asyncio.run(IncidentAnalyzer().analyze(alert1)))
    store.create(alert2, asyncio.run(IncidentAnalyzer().analyze(alert2)))
    store.create(alert3, asyncio.run(IncidentAnalyzer().analyze(alert3)))

    summaries = store.get_source_files_summary()
    assert len(summaries) == 2
    batch_a_summary = next(s for s in summaries if s["source_file"] == "batch_a.json")
    assert batch_a_summary["incident_count"] == 2

    deleted_count = store.delete_by_source_file("batch_a.json")
    assert deleted_count == 2
    remaining = store.list()
    assert len(remaining) == 1
    assert remaining[0].alert.source_file == "batch_b.csv"


def test_soar_playbook_generation(tmp_path):
    from app.services.soar_playbook import SOARPlaybookGenerator

    alert = demo_alert()
    assessment = asyncio.run(IncidentAnalyzer().analyze(alert))
    incident = CaseStore(tmp_path / "cases.db").create(alert, assessment)

    playbook = SOARPlaybookGenerator().generate_playbook(incident)
    assert playbook.incident_id == incident.id
    assert len(playbook.scripts) == 3

    ps_script = next(s for s in playbook.scripts if s.language == "powershell")
    assert "New-NetFirewallRule" in ps_script.code
    assert "198.51.100.10" in ps_script.code

    bash_script = next(s for s in playbook.scripts if s.language == "bash")
    assert "iptables" in bash_script.code
    assert "198.51.100.10" in bash_script.code


def test_stix21_export(tmp_path):
    from app.services.stix_exporter import STIX21Exporter

    alert = demo_alert()
    assessment = asyncio.run(IncidentAnalyzer().analyze(alert))
    incident = CaseStore(tmp_path / "cases.db").create(alert, assessment)

    bundle = STIX21Exporter().export_bundle(incident)
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 3
    assert any(obj["type"] == "indicator" for obj in bundle["objects"])
    assert any(obj["type"] == "attack-pattern" for obj in bundle["objects"])


