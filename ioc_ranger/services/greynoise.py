from __future__ import annotations

import httpx

BASE = "https://api.greynoise.io/v3/community"


async def check_ip(client: httpx.AsyncClient, api_key: str | None, ip: str) -> dict:
    """
    Check IP on GreyNoise Community API.
    Returns dict with noise, riot, classification.
    """
    headers = {}
    if api_key:
        headers["key"] = api_key

    url = f"{BASE}/{ip}"
    try:
        r = await client.get(url, headers=headers, timeout=10)
        if r.status_code == 404:
            return {"noise": False, "riot": False}
        r.raise_for_status()
        data = r.json()
        return {
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
        }
    except Exception:
        return {}
