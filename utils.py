import hashlib
import json
import re
from urllib.parse import urlparse, parse_qs

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "preview.owasp-juice.shop",
}

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def is_allowed_url(url: str):
    try:
        u = urlparse(url)
        if u.scheme not in ALLOWED_SCHEMES:
            return False, f"scheme '{u.scheme}' not allowed"
        if u.hostname not in ALLOWED_HOSTS:
            return False, f"host '{u.hostname}' not allowed"
        return True, "allowed configured scope"
    except Exception as e:
        return False, f"invalid URL: {e}"


def classify_value(value):
    if value is None:
        return "null", "other"
    if isinstance(value, bool):
        return "boolean", "other"
    if isinstance(value, int):
        return "integer", "id-like" if value >= 0 else "other"
    if isinstance(value, float):
        return "float", "other"

    text = str(value).strip()

    if text == "":
        return "empty-string", "other"
    if text.isdigit():
        return "string-numeric", "id-like"
    if UUID_RE.match(text):
        return "uuid", "id-like"
    if EMAIL_RE.match(text):
        return "email", "identity"
    if JWT_RE.match(text):
        return "jwt-like", "token"

    lower = text.lower()
    if lower in {"admin", "user", "customer", "role_admin", "role_user"}:
        return "string", "role"

    return "string", "other"


def determine_auth_state(headers: dict) -> str:
    lower = {k.lower(): v for k, v in headers.items()}
    if lower.get("authorization", "").strip():
        return "bearer-or-auth-header"
    if lower.get("cookie", "").strip():
        return "cookie-auth"
    return "no-auth"


def extract_candidate_inputs(url: str, headers: dict, body: str):
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    candidates = []

    for name, values in query.items():
        sample = values[0] if values else ""
        value_type, classification = classify_value(sample)
        candidates.append({
            "name": name,
            "source": "query",
            "value_type": value_type,
            "classification": classification,
            "sample_value": str(sample)[:160]
        })

    content_type = headers.get("Content-Type", headers.get("content-type", ""))

    if "json" in content_type.lower() and body:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for name, value in data.items():
                    value_type, classification = classify_value(value)
                    candidates.append({
                        "name": name,
                        "source": "json",
                        "value_type": value_type,
                        "classification": classification,
                        "sample_value": str(value)[:160]
                    })
        except Exception:
            pass

    return candidates


def fingerprint_response(body: str):
    if not body:
        return None

    try:
        data = json.loads(body)
        if isinstance(data, dict):
            raw = json.dumps({"type": "dict", "keys": sorted(data.keys())}, sort_keys=True)
            return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
        if isinstance(data, list):
            raw = json.dumps({"type": "list", "length": len(data)}, sort_keys=True)
            return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
    except Exception:
        pass

    return hashlib.sha256(body[:1000].encode("utf-8", errors="ignore")).hexdigest()


def request_hash(method: str, url: str, body: str):
    raw = f"{method}|{url}|{body}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def summarize_response(response_headers: dict, response_body: str):
    json_keys = []
    preview = []

    try:
        data = json.loads(response_body) if response_body else {}
        if isinstance(data, dict):
            json_keys = list(data.keys())[:50]
            for k, v in list(data.items())[:10]:
                if isinstance(v, (str, int, float, bool)) or v is None:
                    preview.append({k: v})
                elif isinstance(v, dict):
                    preview.append({k: {"nested_keys": list(v.keys())[:10]}})
                elif isinstance(v, list):
                    preview.append({k: {"list_length": len(v)}})
        elif isinstance(data, list):
            preview.append({"list_length": len(data)})
    except Exception:
        if response_body:
            preview.append({"text_preview": response_body[:400]})

    return {
        "header_names": list(response_headers.keys())[:30],
        "json_keys": json_keys,
        "preview": preview,
        "response_length": len(response_body.encode("utf-8", errors="ignore")),
        "response_fingerprint": fingerprint_response(response_body),
    }
