"""URL canonicalisation shared by data, model and API."""
from urllib.parse import urlsplit, urlunsplit
import re

_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)

def canonicalize(value: str) -> str:
    if value is None: raise ValueError("URL is required")
    raw = str(value).strip()
    if not raw or any(ord(c) < 32 for c in raw): raise ValueError("URL is empty or contains control characters")
    raw = re.sub(r"^hxxps?://", "https://", raw, flags=re.I).replace("[.]", ".")
    candidate = raw if _SCHEME.match(raw) else "//" + raw
    p = urlsplit(candidate)
    host = (p.hostname or "").lower().rstrip(".")
    if not host: raise ValueError("URL has no host")
    if host.startswith("www") and re.match(r"^www\d*$", host.split('.')[0]):
        host = host.split('.', 1)[1] if '.' in host else host
    try: port = p.port
    except ValueError: raise ValueError("invalid port")
    netloc = host
    if p.username or p.password:
        auth = (p.username or "") + ((":" + p.password) if p.password else "")
        netloc = auth + "@" + host
    if port and not ((p.scheme.lower()=="http" and port==80) or (p.scheme.lower()=="https" and port==443)):
        netloc += f":{port}"
    path = p.path or ""
    if path == "/": path = ""
    # A scheme-less canonical form is represented as host/path (without `//`)
    # so it is stable for storage and safe to pass back through this function.
    return urlunsplit(("", netloc, path, p.query, "")).lstrip("/")

def raw_flags(value: str) -> dict:
    s=str(value).strip(); low=s.lower()
    return {"has_scheme_raw": bool(_SCHEME.match(s)), "has_www_raw": bool(re.match(r"^(?:https?://)?www\d*\.", low)), "has_trailing_slash_raw": low.rstrip().endswith("/")}
