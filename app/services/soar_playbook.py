"""SOAR Containment Playbook Generator Service.

Generates production-grade, executable security scripts (PowerShell, Bash, Firewall CLI)
to isolate endpoints, block malicious IPs, kill rogue processes, and revoke compromised user credentials.
"""

from __future__ import annotations

import re
from typing import Any

from app.schemas import Incident, SOARPlaybookResponse, SOARScript


class SOARPlaybookGenerator:
    """Generates automated SOAR scripts based on telemetry and IOCs from an incident."""

    def generate_playbook(self, incident: Incident) -> SOARPlaybookResponse:
        alert = incident.alert
        assessment = incident.assessment

        # Collect IP indicators
        ips: set[str] = set()
        for ind in assessment.indicators:
            if ind.indicator_type == "ip":
                ips.add(ind.value)

        # Look in raw_event and description for IP patterns if none found
        if not ips:
            found_ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", alert.description)
            for ip in found_ips:
                if not ip.startswith("127.") and not ip.startswith("0."):
                    ips.add(ip)

        # Collect user entities
        users: set[str] = set()
        if "user" in alert.entities:
            users.add(alert.entities["user"])
        if "username" in alert.entities:
            users.add(alert.entities["username"])
        if "account" in alert.entities:
            users.add(alert.entities["account"])

        # Collect host / process entities
        hosts: set[str] = set()
        if "host" in alert.entities:
            hosts.add(alert.entities["host"])
        if "hostname" in alert.entities:
            hosts.add(alert.entities["hostname"])

        pids: set[str] = set()
        if "pid" in alert.entities:
            pids.add(alert.entities["pid"])
        if "process_id" in alert.entities:
            pids.add(alert.entities["process_id"])

        process_names: set[str] = set()
        if "process" in alert.entities:
            process_names.add(alert.entities["process"])
        if "process_name" in alert.entities:
            process_names.add(alert.entities["process_name"])

        # Target entities list
        target_entities = list(ips | users | hosts | process_names)
        if not target_entities:
            target_entities = ["Unknown Target / Telemetry Incomplete"]

        # Build PowerShell Script
        ps_script = self._build_powershell_script(alert.external_id, ips, users, hosts, pids, process_names)
        
        # Build Bash Script
        bash_script = self._build_bash_script(alert.external_id, ips, users, pids, process_names)

        # Build Firewall CLI Script
        fw_script = self._build_firewall_cli_script(alert.external_id, ips)

        return SOARPlaybookResponse(
            incident_id=incident.id,
            target_entities=target_entities,
            scripts=[
                SOARScript(
                    language="powershell",
                    title="Windows & Active Directory SOAR Script",
                    description="Automated PowerShell script for Windows Defender Firewall block, AD user lock, and process kill.",
                    code=ps_script,
                ),
                SOARScript(
                    language="bash",
                    title="Linux & IPTables Containment Script",
                    description="Automated Bash script for IPTables network drop rules, session termination, and service isolation.",
                    code=bash_script,
                ),
                SOARScript(
                    language="cli",
                    title="Palo Alto & Cisco ASA Firewall CLI Playbook",
                    description="Enterprise Firewall CLI commands to block malicious IP infrastructure at the perimeter.",
                    code=fw_script,
                ),
            ],
        )

    def _build_powershell_script(
        self,
        alert_id: str,
        ips: set[str],
        users: set[str],
        hosts: set[str],
        pids: set[str],
        process_names: set[str],
    ) -> str:
        lines = [
            f"# ========================================================",
            f"# SOAR CONTAINMENT PLAYBOOK - POWERSHELL",
            f"# Incident External ID: {alert_id}",
            f"# Purpose: Endpoint Isolation & Host Containment",
            f"# ========================================================",
            f"$ErrorActionPreference = 'Stop'",
            f"Write-Host '[+] Initiating Automated Containment for Incident {alert_id}...' -ForegroundColor Cyan",
            "",
        ]

        if ips:
            lines.append("# 1. Block Malicious Network Infrastructure in Windows Firewall")
            for ip in sorted(ips):
                rule_name = f"SOAR_BLOCK_{alert_id}_{ip.replace('.', '_')}"
                lines.append(
                    f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -Action Block -RemoteAddress '{ip}' -Description 'Automated Incident Response Containment'"
                )
                lines.append(
                    f"New-NetFirewallRule -DisplayName '{rule_name}_Out' -Direction Outbound -Action Block -RemoteAddress '{ip}' -Description 'Automated Incident Response Containment'"
                )
            lines.append("Write-Host '[v] Windows Firewall Inbound & Outbound Block Rules Created.' -ForegroundColor Green")
            lines.append("")

        if users:
            lines.append("# 2. Disable Compromised Active Directory / Local User Accounts")
            for user in sorted(users):
                lines.append(f"try {{ Disable-ADAccount -Identity '{user}' -Confirm:$false; Write-Host '[v] Active Directory Account {user} Disabled.' -ForegroundColor Green }} catch {{ Write-Warning '[!] Failed to disable AD account {user}: $_' }}")
                lines.append(f"try {{ Disable-LocalUser -Name '{user}' -ErrorAction SilentlyContinue }} catch {{}}")
            lines.append("")

        if pids or process_names:
            lines.append("# 3. Terminate Malicious Processes")
            for pid in sorted(pids):
                lines.append(f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue")
            for proc in sorted(process_names):
                lines.append(f"Get-Process -Name '{proc.replace('.exe', '')}' -ErrorAction SilentlyContinue | Stop-Process -Force")
            lines.append("Write-Host '[v] Rogue Process Termination Completed.' -ForegroundColor Green")
            lines.append("")

        lines.append("# 4. Flush DNS Resolver Cache & Reset Connections")
        lines.append("Clear-DnsClientCache")
        lines.append("Write-Host '[v] DNS Cache Flushed. Incident Containment Executed Successfully!' -ForegroundColor Green")

        return "\n".join(lines)

    def _build_bash_script(
        self,
        alert_id: str,
        ips: set[str],
        users: set[str],
        pids: set[str],
        process_names: set[str],
    ) -> str:
        lines = [
            f"#!/usr/bin/env bash",
            f"# ========================================================",
            f"# SOAR CONTAINMENT PLAYBOOK - LINUX BASH",
            f"# Incident External ID: {alert_id}",
            f"# Purpose: Linux IPTables Block & User Isolation",
            f"# ========================================================",
            f"set -euo pipefail",
            f"echo '[+] Executing Linux Containment Playbook for {alert_id}...'",
            "",
        ]

        if ips:
            lines.append("# 1. IPTables Ingress & Egress Drop Rules")
            for ip in sorted(ips):
                lines.append(f"sudo iptables -A INPUT -s {ip} -j DROP -m comment --comment 'SOAR-BLOCK-{alert_id}'")
                lines.append(f"sudo iptables -A OUTPUT -d {ip} -j DROP -m comment --comment 'SOAR-BLOCK-{alert_id}'")
            lines.append("echo '[v] IPTables packet drop rules applied.'")
            lines.append("")

        if users:
            lines.append("# 2. Terminate Active User Sessions & Lock User Account")
            for user in sorted(users):
                lines.append(f"sudo pkill -U {user} -9 || true")
                lines.append(f"sudo usermod -L {user} || true")
            lines.append("echo '[v] Compromised user sessions terminated and accounts locked.'")
            lines.append("")

        if pids or process_names:
            lines.append("# 3. Terminate Suspicious Processes")
            for pid in sorted(pids):
                lines.append(f"sudo kill -9 {pid} || true")
            for proc in sorted(process_names):
                lines.append(f"sudo pkill -f {proc} || true")
            lines.append("echo '[v] Malicious processes terminated.'")
            lines.append("")

        lines.append("echo '[v] Linux Containment Complete.'")
        return "\n".join(lines)

    def _build_firewall_cli_script(self, alert_id: str, ips: set[str]) -> str:
        lines = [
            f"! ========================================================",
            f"! PERIMETER FIREWALL CLI CONTAINMENT PLAYBOOK",
            f"! Incident External ID: {alert_id}",
            f"! ========================================================",
            "",
            f"! --- PALO ALTO NETWORKS PAN-OS CLI ---",
            f"configure",
        ]

        if ips:
            for ip in sorted(ips):
                sanitized_ip = ip.replace(".", "_")
                lines.append(f"set address ADDR_BLOCK_{alert_id}_{sanitized_ip} ip-netmask {ip}/32 description 'SOAR Auto Block Incident {alert_id}'")
                lines.append(f"set address-group BLOCKED_THREAT_INFRASTRUCTURE member ADDR_BLOCK_{alert_id}_{sanitized_ip}")
            lines.append("commit")
            lines.append("exit")
            lines.append("")
            lines.append(f"! --- CISCO ASA / FIREPOWER CLI ---")
            lines.append("configure terminal")
            for ip in sorted(ips):
                lines.append(f"object network OBJ_BLOCK_{ip.replace('.', '_')}")
                lines.append(f" host {ip}")
                lines.append(f"access-list OUTSIDE_BLOCK_ACL extended deny ip host {ip} any")
            lines.append("write memory")
        else:
            lines.append("! No IP indicators extracted from telemetry. Inspect host logs for perimeter rules.")

        return "\n".join(lines)
