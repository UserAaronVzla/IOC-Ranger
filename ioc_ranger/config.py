import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()  # loads .env in cwd

@dataclass
class Settings:
    vt_api_key: str | None
    abuseipdb_key: str | None
    ipqs_key: str | None
    cache_ttl: int

def get_settings() -> Settings:
    return Settings(
        vt_api_key=os.getenv("VT_API_KEY"),
        abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY"),
        ipqs_key=os.getenv("IPQS_API_KEY"),
        cache_ttl=int(os.getenv("CACHE_TTL", "86400")),
    )
