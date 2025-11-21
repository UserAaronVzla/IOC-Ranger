from __future__ import annotations

import httpx

BASE = "https://api.shodan.io"


async def check_ip(client: httpx.AsyncClient, api_key: str | None, ip: str) -> dict:
    """
    Check IP on Shodan.
    Returns dict with ports and vulns.
    """
    if not api_key:
        return {}

    url = f"{BASE}/shodan/host/{ip}"
    params = {"key": api_key, "minify": "true"}
    try:
        r = await client.get(url, params=params, timeout=10)
        if r.status_code == 404:
            return {}
        r.raise_for_status()
        data = r.json()
        return {
            "ports": data.get("ports", []),
            "vulns": list(data.get("vulns", {})) if "vulns" in data else [],
        }
    except Exception:
        return {}
