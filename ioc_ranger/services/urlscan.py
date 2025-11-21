from __future__ import annotations

import httpx

BASE = "https://urlscan.io/api/v1"


async def search_url(client: httpx.AsyncClient, api_key: str | None, url: str) -> dict:
    """
    Search for a URL in URLScan.io.
    Returns dict with uuid, score, screenshot link.
    """
    headers = {}
    if api_key:
        headers["API-Key"] = api_key

    # Search for the exact page URL
    params: dict[str, str | int] = {"q": f'page.url:"{url}"', "size": 1}
    try:
        r = await client.get(f"{BASE}/search/", headers=headers, params=params, timeout=15)
        r.raise_for_status()
        data = r.json()
        results = data.get("results", [])
        if not results:
            return {}

        res = results[0]
        task = res.get("task", {})
        return {
            "uuid": task.get("uuid"),
            "score": res.get("score"),  # Not always present, sometimes in stats
            "screenshot": res.get("screenshot"),
        }
    except Exception:
        return {}
