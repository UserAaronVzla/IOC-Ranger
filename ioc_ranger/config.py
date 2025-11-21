import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    vt_api_key: str | None
    abuseipdb_key: str | None
    ipqs_key: str | None
    alienvault_key: str | None
    urlscan_key: str | None
    shodan_key: str | None
    greynoise_key: str | None
    threatfox_key: str | None
    cache_ttl: int


def get_settings() -> Settings:
    return Settings(
        vt_api_key=os.getenv("VT_API_KEY"),
        abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY"),
        ipqs_key=os.getenv("IPQS_API_KEY"),
        alienvault_key=os.getenv("ALIENVAULT_API_KEY"),
        urlscan_key=os.getenv("URLSCAN_API_KEY"),
        shodan_key=os.getenv("SHODAN_API_KEY"),
        greynoise_key=os.getenv("GREYNOISE_API_KEY"),
        threatfox_key=os.getenv("THREATFOX_API_KEY"),
        cache_ttl=int(os.getenv("CACHE_TTL", "86400")),
    )
