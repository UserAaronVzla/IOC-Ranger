from dataclasses import dataclass, field
from typing import Optional, Literal

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
    is_signed: Optional[bool] = None
    signers: str = ""
    signature_valid: Optional[bool] = None
    vt_link: str = ""

@dataclass
class IPResult:
    ioc: str
    abuse_confidence: Optional[int] = None
    total_reports: Optional[int] = None
    last_reported_at: Optional[str] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    ipqs_fraud_score: Optional[int] = None
    is_proxy: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_tor: Optional[bool] = None
    recent_abuse: Optional[bool] = None

@dataclass
class DomainResult:
    ioc: str
    ipqs_suspicious: Optional[bool] = None
    ipqs_risk_score: Optional[int] = None
    parking: Optional[bool] = None
    spamming: Optional[bool] = None
    malware: Optional[bool] = None

@dataclass
class URLResult:
    ioc: str
    ipqs_suspicious: Optional[bool] = None
    ipqs_risk_score: Optional[int] = None
    phishing: Optional[bool] = None
    malware: Optional[bool] = None
    shortened: Optional[bool] = None

@dataclass
class MixedRow:
    kind: IOCType
    data: HashResult | IPResult | DomainResult | URLResult
    notes: list[str] = field(default_factory=list)
