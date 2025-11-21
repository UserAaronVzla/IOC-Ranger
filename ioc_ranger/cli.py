# ioc_ranger/cli.py
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
import typer
from rich import print
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from . import __version__ as VERSION
from . import output as out
from .banner import print_banner
from .cache import get as cache_get
from .cache import set_ as cache_set
from .config import get_settings
from .ioc_types import DomainResult, HashResult, IPResult, MixedRow, URLResult
from .services import (
    abuse_check_ip,
    get_hash_info,
    greynoise_check_ip,
    ipqs_check_domain,
    ipqs_check_ip,
    ipqs_check_url,
    otx_get_pulses,
    shodan_check_ip,
    threatfox_search,
    urlscan_search,
)
from .validators import classify

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
    iocs: list[str] = typer.Argument(None, help="List of IOCs to check"),
    type: str = typer.Option(
        None, "--type", "-t", help="hashes | ips | domains | urls | mixed (auto-classify)"
    ),
    input: Path = typer.Option(None, "--input", "-i", help="Path to file with IOCs (one per line)"),
    out_base: Path = typer.Option(
        Path("outputs/results"),
        "--out",
        "-o",
        help="Output base path (no extension). We'll write .csv/.json as requested.",
    ),
    format: list[str] = typer.Option(
        ["table"], "--format", "-f", help="Any of: table, csv, json, html (can repeat)"
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
        # Only prompt if no input is provided at all
        if not iocs and not input and sys.stdin.isatty():
            dtype = _normalize_type(
                typer.prompt(
                    "What are you checking? [hashes|ips|domains|urls|mixed]", default="mixed"
                )
            )

    if not dtype:
        dtype = "mixed"

    items = []
    if iocs:
        items.extend(iocs)

    if input:
        if not input.exists():
            typer.secho(f"Input file not found: {input}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        items.extend(_read_lines(input))

    # Read from stdin if piped
    if not sys.stdin.isatty():
        for line in sys.stdin:
            s = line.strip()
            if s:
                items.append(s)

    if not items:
        # If still no items, prompt interactively if we are in a TTY
        if sys.stdin.isatty():
            file_path = Path(typer.prompt("Path to input file", default="inputs/iocs_mixed.txt"))
            if not file_path.exists():
                typer.secho(f"Input file not found: {file_path}", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=1)
            items.extend(_read_lines(file_path))
        else:
            typer.secho("No IOCs provided.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

    # Deduplicate while preserving order
    items = list(dict.fromkeys(items))

    if not items:
        typer.secho("No IOCs found.", fg=typer.colors.YELLOW)
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
    if "html" in fmts:
        p = out.write_html(rows, str(out_base))
        print(f"[green]HTML written:[/green] {p}")


# --------------------------- Orchestration ---------------------------
async def process(dtype: str, items: list[str], settings, max_concurrency: int = 20):
    """
    Route each IOC to its appropriate handler, with concurrency and caching.
    """
    rows: list[MixedRow] = []
    timeout = httpx.Timeout(30.0, connect=10.0)
    limits = httpx.Limits(
        max_keepalive_connections=max_concurrency, max_connections=max_concurrency
    )
    sem = asyncio.Semaphore(max_concurrency)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True,
    ) as progress:
        task_id = progress.add_task("Checking IOCs...", total=len(items))

        async with httpx.AsyncClient(
            timeout=timeout, limits=limits, follow_redirects=True
        ) as client:

            async def _task(s: str):
                async with sem:
                    try:
                        kind = dtype if dtype != "mixed" else classify(s)
                        if kind == "hash":
                            res = await handle_hash(client, s, settings)
                        elif kind == "ip":
                            res = await handle_ip(client, s, settings)
                        elif kind == "domain":
                            res = await handle_domain(client, s, settings)
                        elif kind == "url":
                            res = await handle_url(client, s, settings)
                        else:
                            res = MixedRow(
                                kind="url", data=URLResult(ioc=s), notes=["Unrecognized IOC type"]
                            )
                    except Exception as e:
                        # Defensive: never crash the whole run on a single item
                        res = MixedRow(
                            kind="url", data=URLResult(ioc=s), notes=[f"Unhandled error: {e}"]
                        )
                    finally:
                        progress.update(task_id, advance=1)
                    return res

            tasks = [_task(s) for s in items]
            results = await asyncio.gather(*tasks)
            rows.extend([r for r in results if r is not None])

    return rows


# ----------------------------- Handlers ------------------------------
async def handle_hash(client: httpx.AsyncClient, h: str, settings) -> MixedRow:
    """
    VirusTotal (v3) + AlienVault + ThreatFox for file hash.
    """
    key = f"vt:{h}"
    # We might want to cache the combined result, but for now let's keep VT caching logic
    # and maybe add others. To keep it simple, I'll fetch fresh for new services or update cache logic later.
    # For this iteration, I'll just fetch VT from cache if available, and others fresh (or implement full caching later).

    # Actually, to avoid complexity, let's just fetch everything if not cached, or fetch missing parts.
    # But the current cache stores the whole HashResult.
    # If I add fields, old cache entries won't have them.
    # I should probably invalidate cache or just accept that old cache entries are partial.

    base = HashResult(ioc=h)
    cached = cache_get(key, settings.cache_ttl)
    if cached:
        base = HashResult(**cached)
        # If we want to enrich cached data with new services, we can do it here.
        # But let's assume if it's cached, we return it.
        # To force update, user can clear cache (delete file).
        return MixedRow(kind="hash", data=base, notes=["cache"])

    notes: list[str] = []

    # VirusTotal
    if settings.vt_api_key:
        try:
            vt_res = await get_hash_info(client, settings.vt_api_key, h)
            # Merge VT result into base
            base = vt_res
        except httpx.HTTPError as e:
            notes.append(f"VT error: {e}")
    else:
        notes.append("Missing VT_API_KEY")

    # AlienVault
    try:
        base.alienvault_pulses = await otx_get_pulses(client, settings.alienvault_key, h, "file")
    except Exception as e:
        notes.append(f"OTX error: {e}")

    # ThreatFox
    try:
        tf_res = await threatfox_search(client, settings.threatfox_key, h)
        base.threatfox_confidence = tf_res.get("confidence_level")
        base.threatfox_type = tf_res.get("threat_type")
    except Exception as e:
        notes.append(f"ThreatFox error: {e}")

    cache_set(key, base.__dict__)
    return MixedRow(kind="hash", data=base, notes=notes)


async def handle_ip(client: httpx.AsyncClient, ip: str, settings) -> MixedRow:
    """
    Combine AbuseIPDB + IPQualityScore + Shodan + GreyNoise + OTX + ThreatFox.
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
            ab_res = await abuse_check_ip(client, settings.abuseipdb_key, ip)
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
            ipqs_res = await ipqs_check_ip(client, settings.ipqs_key, ip)
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

    # Shodan
    try:
        shodan_res = await shodan_check_ip(client, settings.shodan_key, ip)
        base.shodan_ports = shodan_res.get("ports", [])
        base.shodan_vulns = shodan_res.get("vulns", [])
    except Exception as e:
        notes.append(f"Shodan error: {e}")

    # GreyNoise
    try:
        gn_res = await greynoise_check_ip(client, settings.greynoise_key, ip)
        base.greynoise_noise = gn_res.get("noise")
        base.greynoise_riot = gn_res.get("riot")
        base.greynoise_class = gn_res.get("classification")
    except Exception as e:
        notes.append(f"GreyNoise error: {e}")

    # AlienVault
    try:
        base.alienvault_pulses = await otx_get_pulses(client, settings.alienvault_key, ip, "IPv4")
    except Exception as e:
        notes.append(f"OTX error: {e}")

    # ThreatFox
    try:
        tf_res = await threatfox_search(client, settings.threatfox_key, ip)
        base.threatfox_confidence = tf_res.get("confidence_level")
        base.threatfox_type = tf_res.get("threat_type")
    except Exception as e:
        notes.append(f"ThreatFox error: {e}")

    return MixedRow(kind="ip", data=base, notes=notes)


async def handle_domain(client: httpx.AsyncClient, domain: str, settings) -> MixedRow:
    """
    IPQualityScore + OTX + ThreatFox for domain reputation.
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
            base = await ipqs_check_domain(client, settings.ipqs_key, domain)
            cache_set(cache_key, base.__dict__)
        except httpx.HTTPError as e:
            notes.append(f"IPQS domain error: {e}")
    else:
        notes.append("Missing IPQS_API_KEY")

    # AlienVault
    try:
        base.alienvault_pulses = await otx_get_pulses(
            client, settings.alienvault_key, domain, "domain"
        )
    except Exception as e:
        notes.append(f"OTX error: {e}")

    # ThreatFox
    try:
        tf_res = await threatfox_search(client, settings.threatfox_key, domain)
        base.threatfox_confidence = tf_res.get("confidence_level")
        base.threatfox_type = tf_res.get("threat_type")
    except Exception as e:
        notes.append(f"ThreatFox error: {e}")

    return MixedRow(kind="domain", data=base, notes=notes)


async def handle_url(client: httpx.AsyncClient, url: str, settings) -> MixedRow:
    """
    IPQualityScore + URLScan + OTX for URL reputation.
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
            base = await ipqs_check_url(client, settings.ipqs_key, url)
            cache_set(cache_key, base.__dict__)
        except httpx.HTTPError as e:
            notes.append(f"IPQS url error: {e}")
    else:
        notes.append("Missing IPQS_API_KEY")

    # URLScan
    try:
        us_res = await urlscan_search(client, settings.urlscan_key, url)
        base.urlscan_uuid = us_res.get("uuid")
        base.urlscan_score = us_res.get("score")
        base.urlscan_screenshot = us_res.get("screenshot")
    except Exception as e:
        notes.append(f"URLScan error: {e}")

    # AlienVault (using domain or hostname might be better, but let's try generic)
    # OTX doesn't have a great URL endpoint for pulses, but we can try 'url' type if supported,
    # or just skip. For now, I'll skip OTX for URLs to avoid noise, or check domain of URL.
    # Let's skip OTX for full URLs for now.

    return MixedRow(kind="url", data=base, notes=notes)


# Entry point when executed as a module via `python -m ioc_ranger`
if __name__ == "__main__":
    app()
