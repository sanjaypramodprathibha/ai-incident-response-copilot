"""Small transparent MITRE ATT&CK rule set for a portfolio demonstration.

Rules intentionally state why they matched. In a production system these would
be versioned detections reviewed by security engineers, not generic keywords.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas import AttackTechnique


@dataclass(frozen=True)
class MitreRule:
    technique_id: str
    name: str
    tactic: str
    terms: tuple[str, ...]
    confidence: int


RULES: tuple[MitreRule, ...] = (
    # Execution & Scripting
    MitreRule("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", ("powershell", "pwsh", "-enc", "encodedcommand", "ps1"), 88),
    MitreRule("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution", ("cmd.exe", "command shell", "batch file"), 78),
    MitreRule("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution", ("bash", "sh", "zsh", "python", "perl"), 75),

    # Credential Access & Auth
    MitreRule("T1110", "Brute Force", "Credential Access", ("failed sign-in", "failed login", "password spray", "authentication failure", "failed password", "login failure"), 85),
    MitreRule("T1003", "OS Credential Dumping", "Credential Access", ("lsass", "mimikatz", "credential dump", "ntds.dit", "sam dump", "procdump"), 90),
    MitreRule("T1555", "Credentials from Password Stores", "Credential Access", ("vault", "keychain", "browser passwords", "kdbx"), 76),

    # Initial Access & Phishing
    MitreRule("T1566", "Phishing", "Initial Access", ("phishing", "credential harvest", "malicious attachment", "suspicious email", "email gateway", "proofpoint"), 82),
    MitreRule("T1190", "Exploit Public-Facing Application", "Initial Access", ("exploit", "sql injection", "xss", "web exploit", "cve-", "vulnerability scan"), 84),

    # Defense Evasion & Persistence
    MitreRule("T1078", "Valid Accounts", "Defense Evasion", ("impossible travel", "successful login after failures", "valid account", "anomalous login"), 74),
    MitreRule("T1562", "Impair Defenses", "Defense Evasion", ("disabled defender", "antivirus stopped", "firewall disabled", "log cleared", "auditpol"), 80),
    MitreRule("T1098", "Account Manipulation", "Persistence", ("added to group", "role assignment", "mailbox delegation", "new oauth consent"), 78),
    MitreRule("T1053", "Scheduled Task/Job", "Persistence", ("scheduled task", "schtasks", "cron", "at.exe"), 80),

    # Command & Control / Network Traffic
    MitreRule("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", ("outbound connection", "malicious ip", "c2", "c2 callback", "beacon", "palo alto", "firewall", "blocked connection", "tor exit"), 80),
    MitreRule("T1105", "Ingress Tool Transfer", "Command and Control", ("certutil", "bitsadmin", "downloadstring", "download cradle", "wget", "curl"), 82),
    MitreRule("T1498", "Network Denial of Service", "Impact", ("ids", "ips", "wireless", "cisco", "rogue ap", "deauth", "dos", "flooding"), 75),

    # Exfiltration & DLP
    MitreRule("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", ("dlp", "data loss", "symantec", "data exfiltration", "unauthorized export", "large transfer"), 82),
    MitreRule("T1041", "Exfiltration Over C2 Channel", "Exfiltration", ("exfiltration", "large upload", "archive uploaded"), 72),
    MitreRule("T1486", "Data Encrypted for Impact", "Impact", ("ransomware", "encrypt", "shadow copies", "vssadmin", "lockbit"), 92),
)


def map_to_mitre(text: str) -> list[AttackTechnique]:
    """Return ATT&CK mappings with the exact matched terms for reviewability."""
    normalized = text.casefold()
    matches: list[AttackTechnique] = []
    for rule in RULES:
        matched_terms = [term for term in rule.terms if term in normalized]
        if matched_terms:
            matches.append(
                AttackTechnique(
                    technique_id=rule.technique_id,
                    name=rule.name,
                    tactic=rule.tactic,
                    reason=f"Matched alert context: {', '.join(matched_terms)}.",
                    confidence=rule.confidence,
                )
            )

    # Intelligent domain fallback inference if no explicit rule matched
    if not matches:
        if "firewall" in normalized or "palo alto" in normalized or "outbound" in normalized or "ip" in normalized:
            matches.append(
                AttackTechnique(
                    technique_id="T1071.001",
                    name="Application Layer Protocol: Web Protocols",
                    tactic="Command and Control",
                    reason="Inferred from network/firewall telemetry context.",
                    confidence=70,
                )
            )
        elif "dlp" in normalized or "symantec" in normalized or "data" in normalized:
            matches.append(
                AttackTechnique(
                    technique_id="T1048",
                    name="Exfiltration Over Alternative Protocol",
                    tactic="Exfiltration",
                    reason="Inferred from Data Loss Prevention (DLP) telemetry.",
                    confidence=75,
                )
            )
        elif "email" in normalized or "proofpoint" in normalized or "mail" in normalized:
            matches.append(
                AttackTechnique(
                    technique_id="T1566",
                    name="Phishing",
                    tactic="Initial Access",
                    reason="Inferred from Email Gateway telemetry.",
                    confidence=75,
                )
            )
        elif "wireless" in normalized or "cisco" in normalized or "ids" in normalized:
            matches.append(
                AttackTechnique(
                    technique_id="T1498",
                    name="Network Denial of Service",
                    tactic="Impact",
                    reason="Inferred from Wireless IDS telemetry.",
                    confidence=70,
                )
            )

    return matches

