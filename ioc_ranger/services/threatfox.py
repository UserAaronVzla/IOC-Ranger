from __future__ import annotations

import httpx

BASE = "https://threatfox-api.abuse.ch/api/v1/"


async def search_ioc(client: httpx.AsyncClient, api_key: str | None, ioc: str) -> dict:
    """
    Search IOC on ThreatFox.
    Returns dict with confidence_level and threat_type.
    """
    headers = {}
    if api_key:
        headers["API-KEY"] = api_key

    payload = {"query": "search_ioc", "search_term": ioc}
    try:
        r = await client.post(BASE, headers=headers, json=payload, timeout=15)
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") != "ok":
            return {}

        # ThreatFox can return multiple entries for one IOC. We take the most recent or highest confidence.
        data_list = data.get("data", [])
        if not data_list:
            return {}

        # Sort by confidence level descending
        best = sorted(data_list, key=lambda x: int(x.get("confidence_level", 0)), reverse=True)[0]
        return {
            "confidence_level": int(best.get("confidence_level", 0)),
            "threat_type": best.get("threat_type"),
        }
    except Exception:
        return {}
