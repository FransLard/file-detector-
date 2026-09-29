from __future__ import annotations
import requests
MB_API = "https://mb-api.abuse.ch/api/v1/"
TIMEOUT = 6

def lookup_sha256(sha256: str) -> dict:
    try:
        r = requests.post(MB_API, data={"query": "get_info", "hash": sha256}, timeout=TIMEOUT)
        j = r.json()
    except Exception as e:
        return {"available": False, "found": False, "reason": f"reputasi offline: {e.__class__.__name__}"}
    if j.get("query_status") != "ok":
        return {"available": True, "found": False, "reason": j.get("query_status", "hash_not_found")}
    data = (j.get("data") or [{}])[0]
    vendors = int(data.get("vendor_intel", {}).get("UNKNOWN", 0) or 0)
    vi = data.get("vendor_intel") or {}
    hits = sum(1 for _k, v in vi.items() if isinstance(v, list) and v and str(v[0]).lower() not in ("clean", "unknown"))
    return {"available": True, "found": True, "family": data.get("signature", "Unknown"), "tags": data.get("tags", []), "file_type": data.get("file_type", ""), "first_seen": data.get("first_seen", ""), "vendor_hits": hits or vendors, "link": f"https://bazaar.abuse.ch/sample/{sha256}/"}
