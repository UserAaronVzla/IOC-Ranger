from __future__ import annotations

import csv
import json
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .ioc_types import MixedRow

console = Console()


def print_table(rows: Sequence[MixedRow]) -> None:
    if not rows:
        console.print("[yellow]No results to display.[/yellow]")
        return

    tbl = Table(title="IOC Ranger results", show_lines=False, header_style="bold cyan")
    tbl.add_column("Type", style="magenta")
    tbl.add_column("IOC", style="white")
    tbl.add_column("Summary", style="green")

    for r in rows:
        k = r.kind
        d = r.data
        if k == "hash":
            summary = (
                f"VT:{'Y' if getattr(d, 'exists_on_vt', False) else 'N'}  "
                f"mal:{getattr(d, 'malicious_vendors', '-')}  "
                f"signed:{'Y' if getattr(d, 'is_signed', False) else 'N'}"
            )
            ioc = d.ioc
        elif k == "ip":
            summary = (
                f"Abuse:{getattr(d, 'abuse_confidence', '-')}  "
                f"IPQS:{getattr(d, 'ipqs_fraud_score', '-')}  "
                f"VPN:{bool(getattr(d, 'is_vpn', False))}  "
                f"Proxy:{bool(getattr(d, 'is_proxy', False))}"
            )
            ioc = d.ioc
        elif k == "domain":
            summary = (
                f"Suspicious:{bool(getattr(d, 'ipqs_suspicious', False))}  "
                f"Risk:{getattr(d, 'ipqs_risk_score', '-')}"
            )
            ioc = d.ioc
        else:  # url
            summary = (
                f"Suspicious:{bool(getattr(d, 'ipqs_suspicious', False))}  "
                f"Risk:{getattr(d, 'ipqs_risk_score', '-')}  "
                f"Phishing:{bool(getattr(d, 'phishing', False))}"
            )
            ioc = d.ioc

        tbl.add_row(k.upper(), ioc, summary)

    console.print(tbl)


def write_csv(rows: Sequence[MixedRow], base_path: str) -> Path:
    p = Path(f"{base_path}.csv")
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "type",
                "ioc",
                "exists_on_vt",
                "malicious_vendors",
                "is_signed",
                "signers",
                "signature_valid",
                "abuse_confidence",
                "total_reports",
                "ipqs_fraud_score",
                "is_proxy",
                "is_vpn",
                "is_tor",
                "ipqs_suspicious",
                "ipqs_risk_score",
                "phishing",
                "malware",
                "alienvault_pulses",
                "shodan_ports",
                "shodan_vulns",
                "greynoise_riot",
                "greynoise_noise",
                "greynoise_class",
                "threatfox_confidence",
                "threatfox_type",
                "urlscan_score",
                "urlscan_screenshot",
                "notes",
            ]
        )
        for r in rows:
            d = r.data
            w.writerow(
                [
                    r.kind,
                    getattr(d, "ioc", ""),
                    getattr(d, "exists_on_vt", ""),
                    getattr(d, "malicious_vendors", ""),
                    getattr(d, "is_signed", ""),
                    getattr(d, "signers", ""),
                    getattr(d, "signature_valid", ""),
                    getattr(d, "abuse_confidence", ""),
                    getattr(d, "total_reports", ""),
                    getattr(d, "ipqs_fraud_score", ""),
                    getattr(d, "is_proxy", ""),
                    getattr(d, "is_vpn", ""),
                    getattr(d, "is_tor", ""),
                    getattr(d, "ipqs_suspicious", ""),
                    getattr(d, "ipqs_risk_score", ""),
                    getattr(d, "phishing", ""),
                    getattr(d, "malware", ""),
                    getattr(d, "alienvault_pulses", ""),
                    str(getattr(d, "shodan_ports", "")),
                    str(getattr(d, "shodan_vulns", "")),
                    getattr(d, "greynoise_riot", ""),
                    getattr(d, "greynoise_noise", ""),
                    getattr(d, "greynoise_class", ""),
                    getattr(d, "threatfox_confidence", ""),
                    getattr(d, "threatfox_type", ""),
                    getattr(d, "urlscan_score", ""),
                    getattr(d, "urlscan_screenshot", ""),
                    "; ".join(r.notes),
                ]
            )
    return p


def write_html(rows: Sequence[MixedRow], base_path: str) -> Path:
    p = Path(f"{base_path}.html")
    p.parent.mkdir(parents=True, exist_ok=True)

    html_rows = []
    for r in rows:
        d = r.data
        # Create a summary string similar to print_table but HTML friendly
        summary = []
        if r.kind == "hash":
            if getattr(d, "exists_on_vt", False):
                summary.append(
                    f"<span class='badge vt'>VT: {getattr(d, 'malicious_vendors', 0)}</span>"
                )
            if getattr(d, "is_signed", False):
                summary.append("<span class='badge good'>Signed</span>")
        elif r.kind == "ip":
            if getattr(d, "abuse_confidence", 0) or 0 > 0:
                summary.append(
                    f"<span class='badge abuse'>Abuse: {getattr(d, 'abuse_confidence', 0)}</span>"
                )
            if getattr(d, "ipqs_fraud_score", 0) or 0 > 75:
                summary.append(
                    f"<span class='badge bad'>Fraud: {getattr(d, 'ipqs_fraud_score', 0)}</span>"
                )
            if getattr(d, "is_vpn", False):
                summary.append("<span class='badge info'>VPN</span>")
            if getattr(d, "shodan_ports", []):
                summary.append(
                    f"<span class='badge info'>Ports: {len(getattr(d, 'shodan_ports', []))}</span>"
                )

        # Add common badges
        if getattr(d, "alienvault_pulses", 0) > 0:
            summary.append(
                f"<span class='badge otx'>OTX: {getattr(d, 'alienvault_pulses', 0)}</span>"
            )
        if getattr(d, "threatfox_confidence", 0) or 0 > 0:
            summary.append(
                f"<span class='badge bad'>ThreatFox: {getattr(d, 'threatfox_confidence', 0)}</span>"
            )

        html_rows.append(f"""
        <tr>
            <td><span class="type-tag {r.kind}">{r.kind.upper()}</span></td>
            <td class="ioc">{getattr(d, "ioc", "")}</td>
            <td>{" ".join(summary)}</td>
            <td class="notes">{"; ".join(r.notes)}</td>
        </tr>
        """)

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IOC Ranger Report</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
            h1 {{ color: #38bdf8; margin-bottom: 2rem; }}
            table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
            th, td {{ padding: 1rem; text-align: left; border-bottom: 1px solid #334155; }}
            th {{ background: #334155; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.875rem; }}
            tr:hover {{ background: #2d3748; }}
            .type-tag {{ padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
            .type-tag.hash {{ background: #8b5cf6; color: white; }}
            .type-tag.ip {{ background: #3b82f6; color: white; }}
            .type-tag.domain {{ background: #10b981; color: white; }}
            .type-tag.url {{ background: #f59e0b; color: white; }}
            .ioc {{ font-family: monospace; color: #e2e8f0; }}
            .badge {{ display: inline-block; padding: 0.125rem 0.375rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 500; margin-right: 0.25rem; background: #475569; color: #e2e8f0; }}
            .badge.vt {{ background: #0ea5e9; color: white; }}
            .badge.abuse {{ background: #facc15; color: black; }}
            .badge.otx {{ background: #f97316; color: white; }}
            .badge.bad {{ background: #ef4444; color: white; }}
            .badge.good {{ background: #22c55e; color: white; }}
            .badge.info {{ background: #64748b; color: white; }}
            .notes {{ color: #94a3b8; font-size: 0.875rem; }}
        </style>
    </head>
    <body>
        <h1>IOC Ranger Report</h1>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>IOC</th>
                    <th>Summary</th>
                    <th>Notes</th>
                </tr>
            </thead>
            <tbody>
                {"".join(html_rows)}
            </tbody>
        </table>
    </body>
    </html>
    """

    p.write_text(html_content, encoding="utf-8")
    return p


def write_json(rows: Sequence[MixedRow], base_path: str) -> Path:
    p = Path(f"{base_path}.json")
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = [{"type": r.kind, "data": r.data.__dict__, "notes": r.notes} for r in rows]
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return p
