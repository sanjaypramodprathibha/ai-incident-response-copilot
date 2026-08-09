"""FastAPI application for the AI Incident Response Copilot."""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from app.schemas import (
    ActionsUpdate,
    AlertInput,
    AuditEvent,
    AuditEventType,
    ContainmentPlanResponse,
    CopilotRequest,
    CopilotResponse,
    EnrichmentResult,
    ExecutiveSummaryResponse,
    IOCSearchResponse,
    Incident,
    IncidentStatus,
    Indicator,
    MitreMatrixResponse,
    NotesUpdate,
    RootCauseAnalysis,
    SOARPlaybookResponse,
    StatusUpdate,
    ThreatIntelSummary,
)
from app.services.ai_explainer import CopilotNarrator
from app.services.analyzer import IncidentAnalyzer
from app.services.reports import incident_markdown, incident_pdf
from app.services.soar_playbook import SOARPlaybookGenerator
from app.services.stix_exporter import STIX21Exporter
from app.services.store import CaseStore
from app.services.threat_intel import ThreatIntelEnricher

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "app" / "data"))
SAMPLE_ALERTS_PATH = BASE_DIR / "app" / "data" / "sample_alerts.json"

store = CaseStore(DATA_DIR / "incidents.db")
analyzer = IncidentAnalyzer()
narrator = CopilotNarrator()
enricher = ThreatIntelEnricher()
soar_generator = SOARPlaybookGenerator()
stix_exporter = STIX21Exporter()
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(
    title="AI Incident Response Copilot",
    version="1.0.0",
    description="Defensive, analyst-in-the-loop incident triage demo.",
    lifespan=lifespan,
)


@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def _not_found(incident_id: str) -> Incident:
    incident = store.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} was not found.")
    return incident


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "ai-incident-response-copilot"}


@app.get("/api/threat-intel/search", response_model=IOCSearchResponse)
async def search_iocs(query: str = Query(min_length=1)) -> IOCSearchResponse:
    res = store.search_iocs(query)
    # Perform live lookup if indicator is searchable and key present
    if not res.enrichment and res.indicator_type in {"ip", "domain", "sha256"}:
        dummy_ind = Indicator(indicator_type=res.indicator_type, value=query, source="IOC Search")
        res.enrichment = await enricher.enrich(dummy_ind)
    return res


@app.get("/api/threat-intel/config")
async def get_threat_intel_config() -> dict[str, Any]:
    return {
        "abuseipdb_configured": bool(enricher.abuseipdb_api_key),
        "virustotal_configured": bool(enricher.vt_api_key),
    }


@app.get("/api/threat-intel/summary", response_model=ThreatIntelSummary)
async def get_threat_intel_summary() -> ThreatIntelSummary:
    return store.get_threat_intel_summary()


@app.get("/api/analytics/mitre-matrix", response_model=MitreMatrixResponse)
async def get_mitre_matrix() -> MitreMatrixResponse:
    return store.get_mitre_matrix()


@app.post("/api/threat-intel/enrich", response_model=EnrichmentResult)
async def enrich_single_ioc(indicator: Indicator) -> EnrichmentResult:
    return await enricher.enrich(indicator)


@app.post("/api/alerts", response_model=Incident, status_code=201)
async def ingest_alert(alert: AlertInput) -> Incident:
    assessment = await analyzer.analyze(alert)
    return store.create(alert, assessment)


@app.post("/api/alerts/bulk", response_model=list[Incident], status_code=201)
async def ingest_alerts(alerts: list[AlertInput]) -> list[Incident]:
    if not alerts:
        raise HTTPException(status_code=400, detail="Provide at least one alert.")
    incidents: list[Incident] = []
    for alert in alerts:
        incidents.append(store.create(alert, await analyzer.analyze(alert)))
    return incidents


@app.post("/api/demo/load", response_model=list[Incident], status_code=201)
async def load_demo_alerts() -> list[Incident]:
    try:
        records = json.loads(SAMPLE_ALERTS_PATH.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=500, detail="Bundled sample alerts could not be loaded.") from error
    return await ingest_alerts([AlertInput.model_validate(record) for record in records])


@app.get("/api/demo/sample-file")
async def download_sample_alert_file():
    if not SAMPLE_ALERTS_PATH.exists():
        raise HTTPException(status_code=404, detail="Sample alerts file not found.")
    return FileResponse(
        path=SAMPLE_ALERTS_PATH,
        filename="sample_alerts.json",
        media_type="application/json"
    )


@app.get("/api/incidents", response_model=list[Incident])
async def list_incidents(status: IncidentStatus | None = Query(default=None)) -> list[Incident]:
    incidents = store.list()
    return [incident for incident in incidents if incident.status == status] if status else incidents


@app.get("/api/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str) -> Incident:
    return _not_found(incident_id)


@app.patch("/api/incidents/{incident_id}", response_model=Incident)
async def set_status(incident_id: str, update: StatusUpdate) -> Incident:
    incident = store.update_status(incident_id, update.status)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} was not found.")
    return incident

@app.patch("/api/incidents/{incident_id}/actions", response_model=Incident)
async def update_actions(
    incident_id: str,
    update: ActionsUpdate
) -> Incident:

    incident = store.update_actions(
        incident_id,
        update.actions
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail=f"Incident {incident_id} was not found."
        )

    return incident

@app.put("/api/incidents/{incident_id}/notes", response_model=Incident)
async def save_notes(incident_id: str, update: NotesUpdate) -> Incident:
    incident = store.update_notes(incident_id, update.notes)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} was not found.")
    return incident


@app.get("/api/incidents/{incident_id}/audit", response_model=list[AuditEvent])
async def get_audit_logs(incident_id: str) -> list[AuditEvent]:
    _not_found(incident_id)
    return store.get_audit_logs(incident_id)


@app.post("/api/incidents/{incident_id}/copilot", response_model=CopilotResponse)
async def copilot(incident_id: str, request: CopilotRequest) -> CopilotResponse:
    incident = _not_found(incident_id)
    answer, provider = narrator.answer(incident, request.question)
    q_text = request.question or "Summarize incident"
    store.add_audit_event(
        incident_id=incident_id,
        event_type=AuditEventType.COPILOT_QUERIED,
        summary=f"AI Copilot queried: '{q_text}' ({provider})",
        details=answer[:120] + "..." if len(answer) > 120 else answer,
        actor="copilot",
    )
    return CopilotResponse(answer=answer, provider=provider)


@app.get("/api/incidents/{incident_id}/containment-plan", response_model=ContainmentPlanResponse)
async def get_containment_plan(incident_id: str) -> ContainmentPlanResponse:
    incident = _not_found(incident_id)
    plan = narrator.generate_containment_plan(incident)
    store.add_audit_event(
        incident_id=incident_id,
        event_type=AuditEventType.ACTION_TAKEN,
        summary="AI Containment Playbook generated",
        details=f"Generated {len(plan.tasks)} containment task items.",
        actor="ai_copilot",
    )
    return plan


@app.get("/api/incidents/{incident_id}/root-cause", response_model=RootCauseAnalysis)
async def get_root_cause(incident_id: str) -> RootCauseAnalysis:
    incident = _not_found(incident_id)
    res = narrator.generate_root_cause(incident)
    store.add_audit_event(
        incident_id=incident_id,
        event_type=AuditEventType.COPILOT_QUERIED,
        summary=f"AI Root Cause generated: '{res.attack_vector}'",
        details=res.root_cause_summary,
        actor="ai_copilot",
    )
    return res


@app.get("/api/incidents/{incident_id}/executive-summary", response_model=ExecutiveSummaryResponse)
async def get_executive_summary(incident_id: str) -> ExecutiveSummaryResponse:
    incident = _not_found(incident_id)
    return narrator.generate_executive_summary(incident)




@app.get("/api/incidents/{incident_id}/report")
async def download_report(incident_id: str, format: str = Query(default="markdown", pattern="^(markdown|pdf)$")) -> Response:
    incident = _not_found(incident_id)
    stem = f"incident-{incident.id}"
    if format == "pdf":
        return Response(
            content=incident_pdf(incident),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{stem}.pdf"'},
        )
    return Response(
        content=incident_markdown(incident),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{stem}.md"'},
    )
@app.get("/api/incidents/{incident_id}/soar-playbook", response_model=SOARPlaybookResponse)
async def get_soar_playbook(incident_id: str) -> SOARPlaybookResponse:
    incident = _not_found(incident_id)
    return soar_generator.generate_playbook(incident)


@app.get("/api/incidents/{incident_id}/stix")
async def download_stix_bundle(incident_id: str) -> Response:
    incident = _not_found(incident_id)
    bundle = stix_exporter.export_bundle(incident)
    stem = f"stix21-incident-{incident.id}"
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/stix+json",
        headers={"Content-Disposition": f'attachment; filename="{stem}.json"'},
    )


@app.get("/api/incidents/sources/list")
async def list_source_files() -> list[dict[str, Any]]:
    return store.get_source_files_summary()


@app.delete("/api/incidents/sources/delete")
async def delete_source_file(filename: str = Query(min_length=1)) -> dict[str, Any]:
    count = store.delete_by_source_file(filename)
    return {"status": "ok", "deleted_count": count, "filename": filename}


@app.delete("/api/incidents/{incident_id}", status_code=204)
async def delete_single_incident(incident_id: str):
    deleted = store.delete_incident(incident_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} was not found.")
    return Response(status_code=204)


@app.delete("/api/incidents", status_code=204)
async def clear_incidents():
    store.clear()
    return Response(status_code=204)