"""Indicator extraction and opt-in enrichment.

The offline response never claims an IOC is malicious. VirusTotal is queried
only for public IPs and only when the user configured its API key.
"""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse

import httpx

from app.schemas import EnrichmentResult, Indicator

IP_PATTERN = re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)")
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|biz|info|test)(?![\w.-])", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_indicators(text: str) -> list[Indicator]:
    """Extract and deduplicate common IOCs from alert text and raw event data."""
    seen: set[tuple[str, str]] = set()
    values: list[Indicator] = []

    def add(indicator_type: str, value: str) -> None:
        key = (indicator_type, value.lower())
        if key not in seen:
            seen.add(key)
            values.append(Indicator(indicator_type=indicator_type, value=value, source="alert context"))

    for value in IP_PATTERN.findall(text):
        add("ip", value.rstrip(".,);]"))
    for value in URL_PATTERN.findall(text):
        add("url", value.rstrip(".,);]"))
    for value in DOMAIN_PATTERN.findall(text):
        hostname = value.lower().rstrip(".,);]")
        if not any(hostname in urlparse(item.value).hostname.lower() for item in values if item.indicator_type == "url" and urlparse(item.value).hostname):
            add("domain", hostname)
    for value in SHA256_PATTERN.findall(text):
        add("sha256", value.lower().rstrip(".,);]"))
    return values


class ThreatIntelEnricher:
    """Provides threat intel enrichment using AbuseIPDB, VirusTotal, and local fallback context."""

    def __init__(
        self,
        vt_api_key: str | None = None,
        abuseipdb_api_key: str | None = None,
    ) -> None:
        self.vt_api_key = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.abuseipdb_api_key = abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY")

    async def enrich_all(self, indicators: list[Indicator]) -> list[EnrichmentResult]:
        return [await self.enrich(indicator) for indicator in indicators]

    async def enrich(self, indicator: Indicator) -> EnrichmentResult:
        local = self._local_context(indicator)

        # 1. Try AbuseIPDB for IP addresses
        if indicator.indicator_type == "ip" and self._is_public_ip(indicator.value):
            if self.abuseipdb_api_key:
                try:
                    return await self._abuseipdb(indicator.value)
                except Exception:
                    pass

        # 2. Try VirusTotal for IP, domain, sha256
        if self.vt_api_key and indicator.indicator_type in {"ip", "domain", "sha256"}:
            if indicator.indicator_type != "ip" or self._is_public_ip(indicator.value):
                try:
                    return await self._virustotal(indicator, local)
                except Exception:
                    pass

        return local

    @staticmethod
    def _is_public_ip(value: str) -> bool:
        try:
            return ipaddress.ip_address(value).is_global
        except ValueError:
            return False

    def _local_context(self, indicator: Indicator) -> EnrichmentResult:
        value = indicator.value
        if indicator.indicator_type == "ip":
            address = ipaddress.ip_address(value)
            if address.is_private or address.is_loopback or address.is_reserved:
                return EnrichmentResult(
                    indicator_type=indicator.indicator_type,
                    value=value,
                    classification="internal",
                    summary="Internal RFC-1918 / Loopback address. Retained as internal infrastructure context.",
                    provider="Local Network",
                    country="LAN",
                    asn="Private Network",
                    reputation_score=0,
                    threat_category="Internal Telemetry",
                )
            else:
                return EnrichmentResult(
                    indicator_type=indicator.indicator_type,
                    value=value,
                    classification="unknown",
                    summary="Public IP address observed in alert telemetry. No live API key configured.",
                    provider="Threat Intel (Local Rule)",
                    country="Global",
                    asn="Public IP",
                    reputation_score=0,
                    threat_category="Public Telemetry",
                )
        elif indicator.indicator_type == "domain":
            return EnrichmentResult(
                indicator_type=indicator.indicator_type,
                value=value,
                classification="unknown",
                summary="Domain observed in alert context; inspect DNS resolve history before blocking.",
                provider="Local Context",
                reputation_score=0,
                threat_category="Domain Name",
            )
        elif indicator.indicator_type == "url":
            return EnrichmentResult(
                indicator_type=indicator.indicator_type,
                value=value,
                classification="unknown",
                summary="URL observed in alert context; inspect payload in sandbox before clicking.",
                provider="Local Context",
                reputation_score=0,
                threat_category="Web Artifact",
            )
        else:
            return EnrichmentResult(
                indicator_type=indicator.indicator_type,
                value=value,
                classification="unknown",
                summary="SHA-256 hash observed; query sandbox or EDR for binary signature match.",
                provider="Local Context",
                reputation_score=0,
                threat_category="Binary Hash",
            )

    async def _abuseipdb(self, ip_address: str) -> EnrichmentResult:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": ""}
        headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}

        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json().get("data", {})

        score = data.get("abuseConfidenceScore", 0)
        country = data.get("countryCode", "UNKNOWN")
        isp = data.get("isp", "Unknown ISP")
        reports = data.get("totalReports", 0)
        usage = data.get("usageType", "Data Center / Hosting / Transit")

        if score >= 50:
            classification = "malicious"
        elif score >= 15:
            classification = "suspicious"
        else:
            classification = "clean"

        return EnrichmentResult(
            indicator_type="ip",
            value=ip_address,
            classification=classification,
            summary=f"AbuseIPDB Score: {score}% ({reports} reports). ISP: {isp}.",
            provider="AbuseIPDB",
            reputation_score=score,
            country=country,
            asn=isp,
            reports_count=reports,
            threat_category=usage,
            details=data,
        )

    async def _virustotal(self, indicator: Indicator, fallback: EnrichmentResult) -> EnrichmentResult:
        endpoint_map = {"ip": "ip_addresses", "domain": "domains", "sha256": "files"}
        value = indicator.value
        if indicator.indicator_type not in endpoint_map:
            return fallback

        endpoint = endpoint_map[indicator.indicator_type]
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/{endpoint}/{value}",
                headers={"x-apikey": self.vt_api_key},
            )
            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]

        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total_engines = sum(stats.values()) if stats else 1

        score = int((malicious + suspicious) / max(total_engines, 1) * 100)
        classification = "malicious" if malicious > 2 else "suspicious" if (malicious > 0 or suspicious > 1) else "clean"

        return EnrichmentResult(
            indicator_type=indicator.indicator_type,
            value=value,
            classification=classification,
            summary=f"VirusTotal Detections: {malicious}/{total_engines} security vendors flagged as malicious.",
            provider="VirusTotal",
            malicious_votes=malicious,
            suspicious_votes=suspicious,
            reputation_score=score,
            threat_category=attributes.get("meaningful_name") or attributes.get("categories", {}).get("Sophos") or "Security Threat",
            first_seen=str(attributes.get("first_submission_date") or ""),
            details={"last_analysis_stats": stats},
        )

