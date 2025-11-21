import json
from pathlib import Path
from time import time
from typing import Any

CACHE_PATH = Path("data/cache.json")


def _load() -> dict[str, Any]:
    if CACHE_PATH.exists():
        try:
            return dict(json.loads(CACHE_PATH.read_text(encoding="utf-8")))
        except Exception:
            return {}
    return {}


def _save(obj: dict) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def get(cache_key: str, ttl: int) -> Any | None:
    db = _load()
    entry = db.get(cache_key)
    if not entry:
        return None
    if time() - entry.get("t", 0) > ttl:
        return None
    return entry.get("v")


def set_(cache_key: str, value: Any) -> None:
    db = _load()
    db[cache_key] = {"t": time(), "v": value}
    _save(db)
