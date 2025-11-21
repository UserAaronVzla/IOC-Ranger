from dataclasses import dataclass, field
from typing import Literal

IOCType = Literal["hash", "ip", "domain", "url"]


@dataclass
class HashResult:
    ioc: str
    exists_on_vt: bool = False
    sha256: str = ""
    primary_name: str = ""
    additional_names: int = 0
    flagged_malicious: bool = False
    malicious_vendors: int = 0
    is_signed: bool | None = None
    signers: str = ""
    signature_valid: bool | None = None
    vt_link: str = ""
    alienvault_pulses: int = 0
    threatfox_confidence: int | None = None
    threatfox_type: str | None = None


@dataclass
class IPResult:
    ioc: str
    abuse_confidence: int | None = None
    total_reports: int | None = None
    last_reported_at: str | None = None
    country: str | None = None
    isp: str | None = None
    org: str | None = None
    ipqs_fraud_score: int | None = None
    is_proxy: bool | None = None
    is_vpn: bool | None = None
    is_tor: bool | None = None
    recent_abuse: bool | None = None
    alienvault_pulses: int = 0
    shodan_ports: list[int] = field(default_factory=list)
    shodan_vulns: list[str] = field(default_factory=list)
    greynoise_riot: bool | None = None
    greynoise_noise: bool | None = None
    greynoise_class: str | None = None
    threatfox_confidence: int | None = None
    threatfox_type: str | None = None


@dataclass
class DomainResult:
    ioc: str
    ipqs_suspicious: bool | None = None
    ipqs_risk_score: int | None = None
    parking: bool | None = None
    spamming: bool | None = None
    malware: bool | None = None
    alienvault_pulses: int = 0
    threatfox_confidence: int | None = None
    threatfox_type: str | None = None


@dataclass
class URLResult:
    ioc: str
    ipqs_suspicious: bool | None = None
    ipqs_risk_score: int | None = None
    phishing: bool | None = None
    malware: bool | None = None
    shortened: bool | None = None
    alienvault_pulses: int = 0
    urlscan_uuid: str | None = None
    urlscan_score: int | None = None
    urlscan_screenshot: str | None = None


@dataclass
class MixedRow:
    kind: IOCType
    data: HashResult | IPResult | DomainResult | URLResult
    notes: list[str] = field(default_factory=list)
