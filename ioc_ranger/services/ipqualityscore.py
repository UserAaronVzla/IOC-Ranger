from __future__ import annotations

import httpx

from ..ioc_types import DomainResult, IPResult, URLResult

BASE = "https://ipqualityscore.com/api/json"


async def check_ip(client: httpx.AsyncClient, api_key: str, ip: str) -> IPResult:
    url = f"{BASE}/ip/{api_key}/{ip}"
    params = {
        "strictness": "1",
        "allow_public_access_points": "true",
        "mobile": "true",
        "fast": "true",
    }
    r = await client.get(url, params=params, timeout=30)
    r.raise_for_status()
    j = r.json() or {}

    return IPResult(
        ioc=ip,
        ipqs_fraud_score=j.get("fraud_score"),
        is_proxy=bool(j.get("proxy")),
        is_vpn=bool(j.get("vpn") or j.get("active_vpn")),
        is_tor=bool(j.get("tor")),
        recent_abuse=bool(j.get("recent_abuse")),
        isp=j.get("ISP") or j.get("isp"),
        org=j.get("organization"),
        country=j.get("country_code") or j.get("country_code_3"),
    )


async def check_domain(client: httpx.AsyncClient, api_key: str, domain: str) -> DomainResult:
    url = f"{BASE}/domain/{api_key}/{domain}"
    params = {"strictness": "1"}
    r = await client.get(url, params=params, timeout=30)
    r.raise_for_status()
    j = r.json() or {}

    return DomainResult(
        ioc=domain,
        ipqs_suspicious=bool(j.get("suspicious")),
        ipqs_risk_score=j.get("risk_score"),
        parking=bool(j.get("parking")),
        spamming=bool(j.get("spamming")),
        malware=bool(j.get("malware")),
    )


async def check_url(client: httpx.AsyncClient, api_key: str, url: str) -> URLResult:
    u = f"{BASE}/url/{api_key}/{url}"
    params = {"strictness": "1"}
    r = await client.get(u, params=params, timeout=45)
    r.raise_for_status()
    j = r.json() or {}

    return URLResult(
        ioc=url,
        ipqs_suspicious=bool(j.get("suspicious")),
        ipqs_risk_score=j.get("risk_score"),
        phishing=bool(j.get("phishing")),
        malware=bool(j.get("malware")),
        shortened=bool(j.get("shortened")),
    )
