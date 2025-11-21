from __future__ import annotations

import httpx

from ..ioc_types import IPResult

BASE = "https://api.abuseipdb.com/api/v2/check"


async def check_ip(client: httpx.AsyncClient, api_key: str, ip: str) -> IPResult:
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "365"}
    r = await client.get(BASE, headers=headers, params=params, timeout=30)
    r.raise_for_status()
    data = (r.json() or {}).get("data") or {}

    return IPResult(
        ioc=ip,
        abuse_confidence=data.get("abuseConfidenceScore"),
        total_reports=data.get("totalReports"),
        last_reported_at=data.get("lastReportedAt"),
        country=data.get("countryCode"),
        isp=data.get("isp"),
        org=data.get("usageType") or data.get("domain"),
    )
