from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv
import os

load_dotenv()

@dataclass
class Settings:
    vt_api_key: Optional[str]
    abuseipdb_key: Optional[str]
    ipqs_key: Optional[str]
    cache_ttl: int

def get_settings() -> Settings:
    return Settings(
        vt_api_key=os.getenv("VT_API_KEY"),
        abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY"),
        ipqs_key=os.getenv("IPQS_API_KEY"),
        cache_ttl=int(os.getenv("CACHE_TTL", "86400")),
    )
