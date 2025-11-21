from __future__ import annotations

import httpx

BASE = "https://otx.alienvault.com/api/v1/indicators"


async def get_pulses(
    client: httpx.AsyncClient, api_key: str | None, ioc: str, ioc_type: str
) -> int:
    """
    Get the number of pulses for an IOC from AlienVault OTX.
    ioc_type: 'IPv4', 'domain', 'file' (hash)
    """
    # OTX allows public access without key for some endpoints, but key is better.
    headers = {}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    url = f"{BASE}/{ioc_type}/{ioc}/general"
    try:
        r = await client.get(url, headers=headers, timeout=10)
        if r.status_code == 404:
            return 0
        r.raise_for_status()
        data = r.json()
        return int(data.get("pulse_info", {}).get("count", 0))
    except Exception:
        return 0
