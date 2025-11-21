from __future__ import annotations

import httpx

from ..ioc_types import HashResult

BASE = "https://www.virustotal.com/api/v3"


def _pick_primary_name(attrs: dict) -> tuple[str, int]:
    primary = attrs.get("meaningful_name") or ""
    names = attrs.get("names") or []
    if not primary and names:
        primary = str(names[0])
    add_count = len({str(n) for n in names if n} - ({primary} if primary else set()))
    return primary, add_count


def _extract_signature(attrs: dict) -> tuple[bool | None, str, bool | None]:
    signers = []
    valid = None
    sig = attrs.get("signature_info") or {}
    if isinstance(sig, dict):
        for k in ("signers", "signer"):
            v = sig.get(k)
            if isinstance(v, list):
                signers += [s for s in v if s]
            elif isinstance(v, str) and v:
                signers.append(v)
        for k in ("publisher", "subject", "issuer", "company_name"):
            v = sig.get(k)
            if isinstance(v, str) and v:
                signers.append(v)
        if "valid" in sig:
            valid = bool(sig["valid"])
        elif "verified" in sig:
            valid = bool(sig["verified"])

    pe = attrs.get("pe_info") or {}
    cert = pe.get("certificate") if isinstance(pe, dict) else None
    if isinstance(cert, dict):
        for k in ("subject", "issuer", "publisher"):
            v = cert.get(k)
            if isinstance(v, str) and v:
                signers.append(v)
        if valid is None and "valid" in cert:
            valid = bool(cert["valid"])

    signers = list(dict.fromkeys([s for s in signers if str(s).strip().lower() != "unsigned"]))
    is_signed = None if not signers else True
    return is_signed, ", ".join(signers) if signers else "", valid


async def get_hash_info(client: httpx.AsyncClient, api_key: str, h: str) -> HashResult:
    headers = {"x-apikey": api_key}
    url = f"{BASE}/files/{h}"
    r = await client.get(url, headers=headers, timeout=30)
    if r.status_code == 404:
        return HashResult(ioc=h, exists_on_vt=False)

    r.raise_for_status()
    obj = r.json()
    attrs = (obj.get("data") or {}).get("attributes") or {}

    last = attrs.get("last_analysis_stats") or {}
    mal = int(last.get("malicious", 0) or 0)

    primary, add_count = _pick_primary_name(attrs)
    is_signed, signers, valid = _extract_signature(attrs)

    sha256 = attrs.get("sha256") or (obj.get("data") or {}).get("id") or ""
    return HashResult(
        ioc=h,
        exists_on_vt=True,
        sha256=sha256,
        primary_name=primary,
        additional_names=add_count,
        malicious_vendors=mal,
        flagged_malicious=mal > 0,
        is_signed=is_signed,
        signers=signers,
        signature_valid=valid,
        vt_link=f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else "",
    )
