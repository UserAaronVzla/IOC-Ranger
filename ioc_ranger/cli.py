# ioc_ranger/cli.py
from __future__ import annotations

from pathlib import Path
import asyncio
from typing import List

import httpx
import typer
from rich import print

from .banner import print_banner
from .config import get_settings
from .validators import classify
from .cache import get as cache_get, set_ as cache_set
from .ioc_types import MixedRow, HashResult, IPResult, DomainResult, URLResult
from .services import virustotal as vt, abuseipdb as ab, ipqualityscore as ipqs
from . import output as out
from . import __version__ as VERSION


app = typer.Typer(add_completion=False)


# --------------------------- Helpers ---------------------------------
def _read_lines(path: Path) -> list[str]:
    """Read non-empty, non-comment lines from a file."""
    items: list[str] = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        items.append(s)
    return items


def _normalize_type(t: str | None) -> str | None:
    """Normalize user-facing plural types to internal singular."""
    if t is None:
        return None
    t = t.strip().lower()
    mapping = {
        "hashes": "hash",
        "ips": "ip",
        "domains": "domain",
        "urls": "url",
        "hash": "hash",
        "ip": "ip",
        "domain": "domain",
        "url": "url",
        "mixed": "mixed",
        "auto": "mixed",
        "all": "mixed",
    }
    return mapping.get(t, t)


# ----------------------------- CLI -----------------------------------
@app.command()
def main(
    type: str = typer.Option(
        None, "--type", "-t", help="hashes | ips | domains | urls | mixed (auto-classify)"
    ),
    input: Path = typer.Option(
        None, "--input", "-i", help="Path to file with IOCs (one per line)"
    ),
    out_base: Path = typer.Option(
        Path("outputs/results"),
        "--out",
        "-o",
        help="Output base path (no extension). We'll write .csv/.json as requested.",
    ),
    format: List[str] = typer.Option(
        ["table"], "--format", "-f", help="Any of: table, csv, json (can repeat)"
    ),
    no_banner: bool = typer.Option(False, "--no-banner", help="Disable banner"),
    concurrency: int = typer.Option(
        20, "--concurrency", "-c", help="Max concurrent requests (default: 20)"
    ),
):
    """
    IOC Ranger — interactive IOC reputation checker.

    Types:
      - hash(es): VirusTotal (detections, signer)
      - ip(s): AbuseIPDB (abuse score) + IPQualityScore (fraud/VPN/Proxy/TOR)
      - domain(s)/url(s): IPQualityScore reputation
      - mixed: auto-classify each line in the input
    """
    if not no_banner:
        print_banner(version=VERSION)

    settings = get_settings()

    dtype = _normalize_type(type)
    if not dtype:
        dtype = _normalize_type(
            typer.prompt("What are you checking? [hashes|ips|domains|urls|mixed]", default="mixed")
        )

    file_path = input
    if not file_path:
        file_path = Path(typer.prompt("Path to input file", default="inputs/iocs_mixed.txt"))
    if not file_path.exists():
        typer.secho(f"Input file not found: {file_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    items = _read_lines(file_path)
    if not items:
        typer.secho("No IOCs found in the input file.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)

    rows = asyncio.run(process(dtype, items, settings, max_concurrency=concurrency))

    # Outputs
    fmts = [f.lower() for f in format]
    if "table" in fmts:
        out.print_table(rows)
    if "csv" in fmts:
        p = out.write_csv(rows, str(out_base))
        print(f"[green]CSV written:[/green] {p}")
    if "json" in fmts:
        p = out.write_json(rows, str(out_base))
        print(f"[green]JSON written:[/green] {p}")


# --------------------------- Orchestration ---------------------------
async def process(dtype: str, items: list[str], settings, max_concurrency: int = 20):
    """
    Route each IOC to its appropriate handler, with concurrency and caching.
    """
    rows: list[MixedRow] = []
    timeout = httpx.Timeout(30.0, connect=10.0)
    limits = httpx.Limits(max_keepalive_connections=max_concurrency, max_connections=max_concurrency)
    sem = asyncio.Semaphore(max_concurrency)

    async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=True) as client:
        async def _task(s: str):
            async with sem:
                try:
                    kind = dtype if dtype != "mixed" else classify(s)
                    if kind == "hash":
                        return await handle_hash(client, s, settings)
                    elif kind == "ip":
                        return await handle_ip(client, s, settings)
                    elif kind == "domain":
                        return await handle_domain(client, s, settings)
                    elif kind == "url":
                        return await handle_url(client, s, settings)
                    else:
                        return MixedRow(kind="url", data=URLResult(ioc=s), notes=["Unrecognized IOC type"])
                except Exception as e:
                    # Defensive: never crash the whole run on a single item
                    return MixedRow(kind="url", data=URLResult(ioc=s), notes=[f"Unhandled error: {e}"])

        tasks = [_task(s) for s in items]
        results = await asyncio.gather(*tasks)
        rows.extend([r for r in results if r is not None])

    return rows


# ----------------------------- Handlers ------------------------------
async def handle_hash(client: httpx.AsyncClient, h: str, settings) -> MixedRow:
    """
    VirusTotal (v3) for file hash:
    - existence on VT
    - last_analysis_stats.malicious
    - names (meaningful_name / names[])
    - signer info (signature_info / pe_info.certificate)
    """
    key = f"vt:{h}"
    cached = cache_get(key, settings.cache_ttl)
    if cached:
        return MixedRow(kind="hash", data=HashResult(**cached), notes=["cache"])

    if not settings.vt_api_key:
        return MixedRow(kind="hash", data=HashResult(ioc=h), notes=["Missing VT_API_KEY"])

    try:
        res = await vt.get_hash_info(client, settings.vt_api_key, h)
        cache_set(key, res.__dict__)
        return MixedRow(kind="hash", data=res)
    except httpx.HTTPError as e:
        return MixedRow(kind="hash", data=HashResult(ioc=h), notes=[f"VT error: {e}"])


async def handle_ip(client: httpx.AsyncClient, ip: str, settings) -> MixedRow:
    """
    Combine AbuseIPDB + IPQualityScore for IP reputation and VPN/Proxy/TOR flags.
    """
    base = IPResult(ioc=ip)
    notes: list[str] = []

    # AbuseIPDB
    cache_key = f"abuse:{ip}"
    cached = cache_get(cache_key, settings.cache_ttl)
    if cached:
        base = IPResult(**cached)
        notes.append("cache:abuseipdb")
    elif settings.abuseipdb_key:
        try:
            ab_res = await ab.check_ip(client, settings.abuseipdb_key, ip)
            base.abuse_confidence = ab_res.abuse_confidence
            base.total_reports = ab_res.total_reports
            base.last_reported_at = ab_res.last_reported_at
            base.country = base.country or ab_res.country
            base.isp = base.isp or ab_res.isp
            base.org = base.org or ab_res.org
            cache_set(cache_key, base.__dict__)
        except httpx.HTTPError as e:
            notes.append(f"AbuseIPDB error: {e}")
    else:
        notes.append("Missing ABUSEIPDB_API_KEY")

    # IPQualityScore
    cache_key2 = f"ipqs-ip:{ip}"
    cached2 = cache_get(cache_key2, settings.cache_ttl)
    if cached2:
        ipqs_res = IPResult(**cached2)
        notes.append("cache:ipqs")
        base.ipqs_fraud_score = ipqs_res.ipqs_fraud_score
        base.is_proxy = ipqs_res.is_proxy
        base.is_vpn = ipqs_res.is_vpn
        base.is_tor = ipqs_res.is_tor
        base.recent_abuse = ipqs_res.recent_abuse
        base.isp = base.isp or ipqs_res.isp
        base.org = base.org or ipqs_res.org
        base.country = base.country or ipqs_res.country
    elif settings.ipqs_key:
        try:
            ipqs_res = await ipqs.check_ip(client, settings.ipqs_key, ip)
            base.ipqs_fraud_score = ipqs_res.ipqs_fraud_score
            base.is_proxy = ipqs_res.is_proxy
            base.is_vpn = ipqs_res.is_vpn
            base.is_tor = ipqs_res.is_tor
            base.recent_abuse = ipqs_res.recent_abuse
            base.isp = base.isp or ipqs_res.isp
            base.org = base.org or ipqs_res.org
            base.country = base.country or ipqs_res.country
            cache_set(cache_key2, IPResult(**base.__dict__).__dict__)
        except httpx.HTTPError as e:
            notes.append(f"IPQS error: {e}")
    else:
        notes.append("Missing IPQS_API_KEY")

    return MixedRow(kind="ip", data=base, notes=notes)


async def handle_domain(client: httpx.AsyncClient, domain: str, settings) -> MixedRow:
    """
    IPQualityScore for domain reputation.
    """
    base = DomainResult(ioc=domain)
    notes: list[str] = []

    cache_key = f"ipqs-domain:{domain}"
    cached = cache_get(cache_key, settings.cache_ttl)
    if cached:
        base = DomainResult(**cached)
        notes.append("cache")
    elif settings.ipqs_key:
        try:
            base = await ipqs.check_domain(client, settings.ipqs_key, domain)
            cache_set(cache_key, base.__dict__)
        except httpx.HTTPError as e:
            notes.append(f"IPQS domain error: {e}")
    else:
        notes.append("Missing IPQS_API_KEY")

    return MixedRow(kind="domain", data=base, notes=notes)


async def handle_url(client: httpx.AsyncClient, url: str, settings) -> MixedRow:
    """
    IPQualityScore for URL reputation (phishing/malware/shortened flags).
    """
    base = URLResult(ioc=url)
    notes: list[str] = []

    cache_key = f"ipqs-url:{url}"
    cached = cache_get(cache_key, settings.cache_ttl)
    if cached:
        base = URLResult(**cached)
        notes.append("cache")
    elif settings.ipqs_key:
        try:
            base = await ipqs.check_url(client, settings.ipqs_key, url)
            cache_set(cache_key, base.__dict__)
        except httpx.HTTPError as e:
            notes.append(f"IPQS url error: {e}")
    else:
        notes.append("Missing IPQS_API_KEY")

    return MixedRow(kind="url", data=base, notes=notes)


# Entry point when executed as a module via `python -m ioc_ranger`
if __name__ == "__main__":
    app()
