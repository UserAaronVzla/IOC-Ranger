from pathlib import Path
from typing import Sequence
import json
import csv
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
            summary = f"VT:{'Y' if getattr(d,'exists_on_vt',False) else 'N'} mal:{getattr(d,'malicious_vendors','-')} signed:{'Y' if getattr(d,'is_signed',False) else 'N'}"
            ioc = d.ioc
        elif k == "ip":
            summary = f"Abuse:{getattr(d,'abuse_confidence','-')} IPQS:{getattr(d,'ipqs_fraud_score','-')} VPN:{bool(getattr(d,'is_vpn',False))} Proxy:{bool(getattr(d,'is_proxy',False))}"
            ioc = d.ioc
        elif k == "domain":
            summary = f"Suspicious:{bool(getattr(d,'ipqs_suspicious',False))} Risk:{getattr(d,'ipqs_risk_score','-')}"
            ioc = d.ioc
        else:
            summary = f"Suspicious:{bool(getattr(d,'ipqs_suspicious',False))} Risk:{getattr(d,'ipqs_risk_score','-')} Phishing:{bool(getattr(d,'phishing',False))}"
            ioc = d.ioc
        tbl.add_row(k.upper(), ioc, summary)

    console.print(tbl)

def write_csv(rows: Sequence[MixedRow], base_path: str) -> Path:
    p = Path(f"{base_path}.csv")
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type","ioc","exists_on_vt","malicious_vendors","is_signed","signers","signature_valid",
                    "abuse_confidence","total_reports","ipqs_fraud_score","is_proxy","is_vpn","is_tor",
                    "ipqs_suspicious","ipqs_risk_score","phishing","malware","notes"])
        for r in rows:
            d = r.data
            w.writerow([
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
                "; ".join(r.notes),
            ])
    return p

def write_json(rows: Sequence[MixedRow], base_path: str) -> Path:
    p = Path(f"{base_path}.json")
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump([{
            "type": r.kind,
            "data": r.data.__dict__,
            "notes": r.notes
        }], f, indent=2, ensure_ascii=False)
    return p
