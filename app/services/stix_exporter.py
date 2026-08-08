"""OASIS STIX 2.1 Standardized Threat Intelligence Exporter.

Generates official STIX 2.1 JSON Threat Exchange bundles containing
Indicators, Attack-Patterns (MITRE ATT&CK), Observed Data, and Relationship SROs.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.schemas import Incident


class STIX21Exporter:
    """Exports an Incident record as a compliant STIX 2.1 JSON Bundle."""

    def export_bundle(self, incident: Incident) -> dict[str, Any]:
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        bundle_id = f"bundle--{uuid.uuid4()}"
        identity_id = f"identity--{uuid.uuid4()}"

        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "Sanjay Pramod Prathibha (AI Incident Response Copilot)",
            "identity_class": "individual",
            "description": "Defensive Security Operations & AI Copilot Platform",
            "contact_information": "LinkedIn: https://www.linkedin.com/in/sanjay-p-p/ | GitHub: https://github.com/sanjaypramodprathibha",
        }

        incident_report_obj = {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{uuid.uuid4()}",
            "created": now_iso,
            "modified": now_iso,
            "name": f"Incident Report: {incident.alert.title}",
            "description": f"Risk Score: {incident.assessment.risk_score}/100 | Severity: {incident.assessment.priority} | Source: {incident.alert.source}",
            "published": now_iso,
            "object_refs": [identity_id],
            "labels": ["threat-report", "incident-response", incident.assessment.priority.value],
        }

        objects: list[dict[str, Any]] = [identity_obj, incident_report_obj]

        # STIX Attack-Patterns (MITRE ATT&CK)
        attack_pattern_refs: list[str] = []
        for tech in incident.assessment.mitre_techniques:
            ap_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, tech.technique_id)}"
            ap_obj = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now_iso,
                "modified": now_iso,
                "name": tech.name,
                "description": tech.reason,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech.technique_id,
                        "url": f"https://attack.mitre.org/techniques/{tech.technique_id.replace('.', '/')}/",
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": tech.tactic.lower().replace(" ", "-"),
                    }
                ],
            }
            objects.append(ap_obj)
            attack_pattern_refs.append(ap_id)
            incident_report_obj["object_refs"].append(ap_id)

        # STIX Indicators & Relationships
        for ind in incident.assessment.indicators:
            pattern = ""
            if ind.indicator_type == "ip":
                pattern = f"[ipv4-addr:value = '{ind.value}']"
            elif ind.indicator_type == "domain":
                pattern = f"[domain-name:value = '{ind.value}']"
            elif ind.indicator_type == "url":
                pattern = f"[url:value = '{ind.value}']"
            elif ind.indicator_type in {"sha256", "md5"}:
                hash_type = "SHA-256" if ind.indicator_type == "sha256" else "MD5"
                pattern = f"[file:hashes.'{hash_type}' = '{ind.value}']"
            else:
                pattern = f"[artifact:payload_bin = '{ind.value}']"

            ind_id = f"indicator--{uuid.uuid4()}"
            ind_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"{ind.indicator_type.upper()} IOC: {ind.value}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_iso,
                "indicator_types": ["malicious-activity"],
            }
            objects.append(ind_obj)
            incident_report_obj["object_refs"].append(ind_id)

            # Link Indicator -> Attack Pattern (SRO Relationship)
            for ap_id in attack_pattern_refs:
                rel_id = f"relationship--{uuid.uuid4()}"
                rel_obj = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap_id,
                }
                objects.append(rel_obj)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }
