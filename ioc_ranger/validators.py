import re

import tldextract

_md5 = re.compile(r"^[a-fA-F0-9]{32}$")
_sha1 = re.compile(r"^[a-fA-F0-9]{40}$")
_sha256 = re.compile(r"^[a-fA-F0-9]{64}$")
_ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_url = re.compile(r"^(https?://)", re.IGNORECASE)


def is_hash(s: str) -> bool:
    return bool(_md5.match(s) or _sha1.match(s) or _sha256.match(s))


def is_ip(s: str) -> bool:
    if not _ipv4.match(s):
        return False
    return all(0 <= int(o) <= 255 for o in s.split("."))


def is_url(s: str) -> bool:
    return bool(_url.match(s))


def is_domain(s: str) -> bool:
    if is_url(s) or is_ip(s):
        return False
    ext = tldextract.extract(s)
    return bool(ext.domain and ext.suffix)


def classify(s: str) -> str:
    s = s.strip()
    if is_hash(s):
        return "hash"
    if is_ip(s):
        return "ip"
    if is_url(s):
        return "url"
    if is_domain(s):
        return "domain"
    return "unknown"
