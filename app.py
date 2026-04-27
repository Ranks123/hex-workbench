import os
import json
import sqlite3
import hashlib
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask, request, jsonify, Response

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import ipaddress
import socket
import logging
import uuid
import time
import re

# ============================================
# CONFIG
# ============================================

DB_PATH = os.environ.get("HEX_WORKBENCH_DB", "observations.db")
API_KEY = os.environ.get("GATEWAY_API_KEY")
VERIFY_SSL = os.environ.get("GATEWAY_VERIFY_SSL", "false").lower() == "true"
PROGRAM_SCOPE_POLICIES_JSON = os.environ.get("HEX_PROGRAM_SCOPE_POLICIES_JSON", "")

AUTO_MUTATION_ENABLED = os.environ.get("HEX_AUTO_MUTATION_ENABLED", "true").lower() == "true"
AUTO_MUTATION_LIMIT = int(os.environ.get("HEX_AUTO_MUTATION_LIMIT", "4"))
AUTO_MUTATION_TIMEOUT = int(os.environ.get("HEX_AUTO_MUTATION_TIMEOUT", "8"))

MULTI_AUTH_ENABLED = os.environ.get("HEX_MULTI_AUTH_ENABLED", "true").lower() == "true"
MULTI_AUTH_LIMIT = int(os.environ.get("HEX_MULTI_AUTH_LIMIT", "6"))
MULTI_AUTH_TIMEOUT = int(os.environ.get("HEX_MULTI_AUTH_TIMEOUT", "8"))
MULTI_AUTH_PROFILES_JSON = os.environ.get("HEX_MULTI_AUTH_PROFILES_JSON", "")
MULTI_AUTH_PROFILES_FILE = os.environ.get(
    "HEX_MULTI_AUTH_PROFILES_FILE",
    "multi_auth_profiles.json"
)

AUTO_EXPLOIT_REPLAY_ENABLED = os.environ.get("HEX_AUTO_EXPLOIT_REPLAY_ENABLED", "true").lower() == "true"
AUTO_EXPLOIT_REPLAY_LIMIT = int(os.environ.get("HEX_AUTO_EXPLOIT_REPLAY_LIMIT", "4"))
AUTO_EXPLOIT_REPLAY_ROUNDS = int(os.environ.get("HEX_AUTO_EXPLOIT_REPLAY_ROUNDS", "2"))
AUTO_EXPLOIT_REPLAY_TIMEOUT = int(os.environ.get("HEX_AUTO_EXPLOIT_REPLAY_TIMEOUT", "8"))
EXPLOIT_WEBHOOK_URL = os.environ.get("HEX_EXPLOIT_WEBHOOK_URL", "")

ALLOWED_TARGET_HOSTS = [
    h.strip().lower()
    for h in os.environ.get("HEX_ALLOWED_TARGET_HOSTS", "").split(",")
    if h.strip()
]

ALLOW_PRIVATE_HOSTS = os.environ.get("HEX_ALLOW_PRIVATE_HOSTS", "false").lower() == "true"
ALLOW_LOCALHOST_TARGETS = os.environ.get("HEX_ALLOW_LOCALHOST_TARGETS", "false").lower() == "true"

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BUSINESS_KEYWORDS = [
    "cart", "basket", "order", "checkout", "wallet", "payment",
    "invoice", "billing", "account", "user", "profile", "address",
    "review", "subscription", "ticket", "booking", "reservation",
    "delivery", "coupon", "discount", "refund", "balance"
]

ROLE_TERMS = ["role", "roles", "permission", "permissions", "scope", "admin", "isadmin"]
IDENTITY_TERMS = ["user", "userid", "user_id", "email", "username", "phone", "account", "customer", "member"]
ID_LIKE_TERMS = [
    "id", "_id", "basket", "basket_id", "order", "order_id", "invoice",
    "invoice_id", "payment", "payment_id", "wallet", "wallet_id",
    "review", "review_id", "product", "product_id", "ticket", "ticket_id",
    "booking", "booking_id", "reservation", "reservation_id", "profile", "profile_id",
    "address", "address_id", "deliverymethodid", "delivery_method_id", "paymentid"
]

GENERIC_NOISE_QUERY_NAMES = {"eio", "t", "sid", "transport", "v", "ts", "_"}

PUBLIC_RESOURCE_FAMILIES = {
    "product", "products",
    "search", "catalog",
    "delivery", "deliverys",
    "review", "reviews",
    "cards"
}

OWNERSHIP_RESOURCE_FAMILIES = {
    "basket", "baskets",
    "basketitem", "basketitems",
    "wallet", "wallets",
    "address", "addresss", "addresses",
    "order", "orders",
    "invoice", "invoices",
    "payment", "payments",
    "account", "accounts",
    "profile", "profiles",
    "user", "users",
    "customer", "customers"
}

# ============================================
# APP
# ============================================

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

LOG_LEVEL = os.environ.get("HEX_LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s"
)

logger = logging.getLogger("hex_workbench")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute", "20 per second"]
)

# ============================================
# DB
# ============================================

def get_db():
    conn = sqlite3.connect(
        DB_PATH,
        check_same_thread=False,
        timeout=10
    )
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")

    return conn

def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program TEXT NOT NULL DEFAULT 'local-lab',
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            query TEXT,
            status_code INTEGER NOT NULL,
            response_length INTEGER NOT NULL,
            auth_state TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_graph_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program TEXT NOT NULL DEFAULT 'local-lab',
            node_id TEXT NOT NULL,
            normalized_path TEXT NOT NULL,
            method TEXT NOT NULL,
            last_path TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            times_seen INTEGER NOT NULL DEFAULT 1,
            UNIQUE(program, node_id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_graph_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program TEXT NOT NULL DEFAULT 'local-lab',
            from_node TEXT NOT NULL,
            to_token TEXT NOT NULL,
            edge_kind TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            times_seen INTEGER NOT NULL DEFAULT 1,
            UNIQUE(program, from_node, to_token, edge_kind)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_graph_auth_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program TEXT NOT NULL DEFAULT 'local-lab',
            node_id TEXT NOT NULL,
            auth_state TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            times_seen INTEGER NOT NULL DEFAULT 1,
            UNIQUE(program, node_id, auth_state)
        )
    """)

    # Phase 3 tables
    conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT,
            normalized_path TEXT,
            family TEXT,
            score INTEGER,
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_state_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT,
            normalized_path TEXT,
            auth_state TEXT,
            status_code INTEGER,
            created_at TEXT
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_observations_program_method_path
        ON observations(program, method, path)
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS pivot_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT NOT NULL,
            seed_path TEXT NOT NULL,
            pivot_target TEXT NOT NULL,
            pivot_value TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER,
            length INTEGER,
            fingerprint TEXT,
            verdict TEXT,
            score INTEGER,
            field_diff_summary TEXT,
            error TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_pivot_trace_id ON pivot_attempts(trace_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_pivot_url ON pivot_attempts(url)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_observations_program_path
        ON observations(program, path)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_observations_program_created_at
        ON observations(program, created_at)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_graph_nodes_program_node
        ON endpoint_graph_nodes(program, node_id)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_graph_nodes_program_norm
        ON endpoint_graph_nodes(program, normalized_path)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_graph_edges_program_from_node
        ON endpoint_graph_edges(program, from_node)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_graph_auth_program_node
        ON endpoint_graph_auth_patterns(program, node_id)
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS attack_paths (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT NOT NULL,
            program TEXT NOT NULL DEFAULT 'local-lab',
            chain_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(trace_id) REFERENCES trace_runs(trace_id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_attack_paths_trace_id ON attack_paths(trace_id)
    """)

    conn.commit()
    conn.close()

init_db()

# ============================================
# TRACE RUN STORAGE
# ============================================

def init_trace_runs_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trace_runs (
            trace_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            program TEXT,
            method TEXT,
            path TEXT,
            url TEXT,
            request_headers_json TEXT,
            request_body TEXT,
            current_json TEXT,
            candidate_inputs_json TEXT,
            attack_chain_json TEXT,
            mutation_output_json TEXT,
            multi_auth_output_json TEXT,
            corroboration_json TEXT,
            exploit_output_json TEXT
        )
    """)
    # Create indexes after table exists
    conn.execute("CREATE INDEX IF NOT EXISTS idx_trace_runs_created_at ON trace_runs(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_trace_runs_program_created_at ON trace_runs(program, created_at)")
    conn.commit()

def save_trace_run(
    trace_id: str,
    program: str,
    method: str,
    path: str,
    url: str,
    request_headers: dict,
    request_body: str,
    current: dict,
    candidate_inputs: list,
    attack_chain: dict,
    mutation_output: dict,
    multi_auth_output: dict,
    corroboration: dict,
    exploit_output: dict
):
    conn = get_db()
    init_trace_runs_table(conn)

    conn.execute("""
        INSERT OR REPLACE INTO trace_runs (
            trace_id,
            created_at,
            program,
            method,
            path,
            url,
            request_headers_json,
            request_body,
            current_json,
            candidate_inputs_json,
            attack_chain_json,
            mutation_output_json,
            multi_auth_output_json,
            corroboration_json,
            exploit_output_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        trace_id,
        datetime.now(timezone.utc).isoformat(),
        program,
        method,
        path,
        url,
        json.dumps(make_json_safe(request_headers or {})),
        request_body or "",
        json.dumps(make_json_safe(current or {})),
        json.dumps(make_json_safe(candidate_inputs or [])),
        json.dumps(make_json_safe(attack_chain or {})),
        json.dumps(make_json_safe(mutation_output or {})),
        json.dumps(make_json_safe(multi_auth_output or {})),
        json.dumps(make_json_safe(corroboration or {})),
        json.dumps(make_json_safe(exploit_output or {}))
    ))
    conn.commit()
    conn.close()


def load_trace_run(trace_id: str):
    conn = get_db()
    init_trace_runs_table(conn)
    row = conn.execute("""
        SELECT *
        FROM trace_runs
        WHERE trace_id = ?
        LIMIT 1
    """, (trace_id,)).fetchone()
    conn.close()

    if not row:
        return None

    return {
        "trace_id": row["trace_id"],
        "created_at": row["created_at"],
        "program": row["program"],
        "method": row["method"],
        "path": row["path"],
        "url": row["url"],
        "request_headers": safe_json_loads(row["request_headers_json"]) or {},
        "request_body": row["request_body"] or "",
        "current": safe_json_loads(row["current_json"]) or {},
        "candidate_inputs": safe_json_loads(row["candidate_inputs_json"]) or [],
        "attack_chain": safe_json_loads(row["attack_chain_json"]) or {},
        "mutation_output": safe_json_loads(row["mutation_output_json"]) or {},
        "multi_auth_output": safe_json_loads(row["multi_auth_output_json"]) or {},
        "corroboration": safe_json_loads(row["corroboration_json"]) or {},
        "exploit_output": safe_json_loads(row["exploit_output_json"]) or {}
    }

# ============================================
# AUTH
# ============================================

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not API_KEY:
            return jsonify({
                "ok": False,
                "error": "Server misconfiguration: GATEWAY_API_KEY is not set"
            }), 500

        supplied = request.headers.get("X-API-Key", "")
        if not supplied or supplied != API_KEY:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        return f(*args, **kwargs)
    return wrapper

# ============================================
# GENERIC HELPERS
# ============================================

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def fp(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()


def get_http_session():
    session = requests.Session()
    retries = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = VERIFY_SSL
    return session


def extract_path(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.path or "/"
    except Exception:
        return "/"


def extract_query(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.query or ""
    except Exception:
        return ""


def detect_auth(headers: dict) -> str:
    normalized = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if normalized.get("authorization"):
        return "bearer-or-auth-header"
    if normalized.get("cookie"):
        return "cookie-auth"
    return "no-auth"


def looks_like_json(text: str) -> bool:
    s = (text or "").strip()
    return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))


def safe_json_loads(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None

def safe_get(d, key, default=None):
    if not isinstance(d, dict):
        return default
    return d.get(key, default)


def safe_int(value, default=0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def severity_rank(value: str) -> int:
    ranks = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1
    }
    return ranks.get(str(value or "").lower(), 0)


def priority_rank(value: str) -> int:
    ranks = {
        "high": 3,
        "medium": 2,
        "low": 1
    }
    return ranks.get(str(value or "").lower(), 0)

def safe_list(value):
    return value if isinstance(value, list) else []

def flatten_json(obj, prefix=""):
    items = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                items.extend(flatten_json(v, key))
            else:
                items.append((key, v))

    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                items.extend(flatten_json(v, key))
            else:
                items.append((key, v))

    return items


def infer_value_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "object"

    s = str(value)
    if s == "":
        return "empty-string"
    if s.isdigit():
        return "string-numeric"
    return "string"


def classify_param(name: str, value) -> str:
    lname = (name or "").lower()

    if any(term in lname for term in ROLE_TERMS):
        return "role"
    if any(term in lname for term in IDENTITY_TERMS):
        return "identity"
    if any(term in lname for term in ID_LIKE_TERMS):
        return "id-like"

    if isinstance(value, str) and value.isdigit():
        return "id-like"

    return "generic"


def is_hash_like_segment(seg: str) -> bool:
    s = (seg or "").strip()
    if len(s) not in (8, 16, 24, 32, 36, 40):
        return False
    return any(c.isdigit() for c in s) and any(c.isalpha() for c in s)


def is_id_like_path(path: str) -> bool:
    parts = [p for p in path.split("/") if p]
    for part in parts:
        if part.isdigit():
            return True
        if is_hash_like_segment(part):
            return True
    return False


def is_business_path(path: str) -> bool:
    p = (path or "").lower()
    return any(k in p for k in BUSINESS_KEYWORDS)

def path_resource_family(path: str) -> str:
    parts = [p.strip().lower() for p in (path or "").split("/") if p.strip()]
    if not parts:
        return ""

    # Prefer the last non-id segment
    for part in reversed(parts):
        if part.isdigit():
            continue
        if is_hash_like_segment(part):
            continue
        return part

    return ""

# ========== PHASE 3: INTELLIGENCE HELPERS ==========
def normalize_path_shape(path: str) -> str:
    """Alias for normalize_path_for_graph – keeps naming consistent."""
    return normalize_path_for_graph(path)

def extract_resource_family(path: str) -> str:
    return path_resource_family(path)

def summarize_auth_state_from_headers(headers: dict) -> str:
    """Reuse existing detect_auth."""
    return detect_auth(headers)

def build_endpoint_intelligence(trace_bundle: dict) -> dict:
    req_headers = trace_bundle.get("request_headers", {})
    resp_text = trace_bundle.get("response_text", "")
    path = trace_bundle.get("path", "")
    method = trace_bundle.get("method", "GET")
    status_code = trace_bundle.get("status_code", 0)

    return {
        "path": path,
        "method": method,
        "normalized_path": normalize_path_shape(path),
        "family": extract_resource_family(path),
        "status_code": status_code,
        "content_length": len(resp_text),
        "has_json": "application/json" in str(req_headers.get("Content-Type", "")).lower(),
        "mentions_error": "error" in resp_text.lower(),
        "mentions_admin": "admin" in resp_text.lower(),
        "mentions_userid": "userid" in resp_text.lower() or "userId" in resp_text,
        "has_object_id_surface": is_id_like_path(path),
        "is_action_endpoint": any(x in path.lower() for x in ["checkout","delete","update","pay","reset","cancel"])
    }

def score_endpoint_intelligence(intel: dict) -> int:
    score = 0
    if intel.get("has_object_id_surface"): score += 20
    if intel.get("is_action_endpoint"): score += 20
    if intel.get("has_json"): score += 10
    if intel.get("mentions_userid"): score += 15
    if intel.get("mentions_admin"): score += 20
    if 200 <= intel.get("status_code", 0) < 300: score += 10
    if intel.get("mentions_error"): score += 5
    if intel.get("content_length", 0) > 100: score += 5
    return min(score, 100)

def choose_next_actions(trace_bundle: dict, intel: dict, score: int) -> list:
    actions = []
    if intel.get("has_object_id_surface"):
        actions.append({"action": "run_id_mutation_tests", "priority": "high", "reason": "Object-like path detected"})
    if intel.get("is_action_endpoint"):
        actions.append({"action": "compare_read_vs_action_authorization", "priority": "high", "reason": "Action endpoint may have weaker auth"})
    if score >= 50:
        actions.append({"action": "run_multi_auth_replay", "priority": "high", "reason": "High endpoint score"})
    family = intel.get("family")
    if family and family not in ("unknown", ""):
        actions.append({"action": "pivot_same_family_endpoints", "priority": "medium", "reason": f"Related family: {family}"})
    return actions

def is_public_resource_family_name(name: str) -> bool:
    return str(name or "").strip().lower() in PUBLIC_RESOURCE_FAMILIES


def is_ownership_resource_family_name(name: str) -> bool:
    return str(name or "").strip().lower() in OWNERSHIP_RESOURCE_FAMILIES


def is_public_resource_path(path: str) -> bool:
    fam = path_resource_family(path)
    return is_public_resource_family_name(fam)


def is_ownership_resource_path(path: str) -> bool:
    fam = path_resource_family(path)
    return is_ownership_resource_family_name(fam)

def response_json_fields(response_text: str):
    loaded = safe_json_loads(response_text)
    if loaded is None:
        return {}

    fields = {}

    def walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else k
                walk(v, key)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                key = f"{prefix}[{i}]"
                walk(v, key)
        else:
            fields[prefix] = str(obj)

    walk(loaded)
    return fields

def normalize_response_text(text: str) -> str:
    if not text:
        return ""

    s = text

    # Remove common dynamic patterns
    replacements = [
        r'"csrf[^"]*"\s*:\s*"[^"]+"',
        r'"token[^"]*"\s*:\s*"[^"]+"',
        r'"auth[^"]*"\s*:\s*"[^"]+"',
        r'"session[^"]*"\s*:\s*"[^"]+"',
        r'"timestamp[^"]*"\s*:\s*"[^"]+"',
        r'"created_at"\s*:\s*"[^"]+"',
        r'"updated_at"\s*:\s*"[^"]+"',
        r'"expires[^"]*"\s*:\s*"[^"]+"',
    ]

    import re
    for pattern in replacements:
        s = re.sub(pattern, '"__filtered__":"__filtered__"', s, flags=re.IGNORECASE)

    # Remove long numeric sequences (IDs, timestamps)
    s = re.sub(r'\b\d{8,}\b', '0', s)

    return s

def stable_fingerprint(text: str) -> str:
    normalized = normalize_response_text(text)
    return fp(normalized)


def normalize_field_value(value):
    s = str(value)

    import re
    s = re.sub(r'\b\d{8,}\b', '0', s)

    if len(s) >= 20 and any(c.isdigit() for c in s) and any(c.isalpha() for c in s):
        return "__dynamic__"

    return s


def normalized_response_fields(response_text: str):
    raw = response_json_fields(response_text)
    return {k: normalize_field_value(v) for k, v in raw.items()}


def diff_response_fields(base_fields: dict, mutated_fields: dict):
    changed = []
    added = []
    removed = []

    base_keys = set(base_fields.keys())
    mut_keys = set(mutated_fields.keys())

    for k in sorted(base_keys & mut_keys):
        if base_fields[k] != mutated_fields[k]:
            changed.append({
                "field": k,
                "before": base_fields[k],
                "after": mutated_fields[k]
            })

    for k in sorted(mut_keys - base_keys):
        added.append({
            "field": k,
            "value": mutated_fields[k]
        })

    for k in sorted(base_keys - mut_keys):
        removed.append({
            "field": k,
            "value": base_fields[k]
        })

    return {
        "changed": changed,
        "added": added,
        "removed": removed
    }


def sensitive_field_name(field_name: str) -> bool:
    lname = (field_name or "").strip().lower()

    # Strong ownership / authorization indicators
    strong_terms = [
        "userid", "user.id", "user_id",
        "owner", "owner.id", "owner_id",
        "account", "account.id", "account_id",
        "customer", "customer.id", "customer_id",
        "basketid", "basket.id", "basket_id",
        "basketitem", "basketitem.id", "basketitem_id",
        "wallet", "wallet.id", "walletid", "wallet_id",
        "address", "address.id", "addressid", "address_id",
        "order", "order.id", "orderid", "order_id",
        "invoice", "invoice.id", "invoiceid", "invoice_id",
        "payment", "payment.id", "paymentid", "payment_id",
        "profile", "profile.id", "profile_id",
        "role", "roles", "permission", "permissions",
        "email", "username"
    ]

    # Weak/general fields that should NOT alone imply IDOR
    weak_exact = {
        "id", "data.id", "name", "data.name", "description",
        "data.description", "image", "data.image",
        "price", "data.price", "deluxeprice", "data.deluxeprice"
    }

    if lname in weak_exact:
        return False

    return any(term in lname for term in strong_terms)

def is_ip_private_or_local(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )
    except ValueError:
        return False


def resolve_host_ips(host: str):
    ips = set()
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            sockaddr = info[4]
            if sockaddr and len(sockaddr) > 0:
                ips.add(sockaddr[0])
    except Exception:
        pass
    return sorted(ips)

def replay_error_kind(error_text: str) -> str:
    s = (error_text or "").lower()

    if "blocked replay target" in s:
        return "policy-block"
    if "connection refused" in s:
        return "target-unreachable"
    if "max retries exceeded" in s:
        return "target-unreachable"
    if "read timed out" in s or "connect timeout" in s or "timed out" in s:
        return "target-timeout"
    if "name or service not known" in s or "failed to resolve" in s:
        return "dns-failure"

    return "request-failure"

def host_is_private_or_local(host: str) -> bool:
    host = (host or "").strip().lower()
    if not host:
        return True

    if host in {"localhost", "ip6-localhost"}:
        return True

    if is_ip_private_or_local(host):
        return True

    for ip in resolve_host_ips(host):
        if is_ip_private_or_local(ip):
            return True

    return False


def target_host_allowed(url: str):
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()

        if scheme not in {"http", "https"}:
            return False, f"disallowed URL scheme: {scheme or 'missing'}"

        if not host:
            return False, "missing target host"

        if ALLOWED_TARGET_HOSTS:
            if host not in ALLOWED_TARGET_HOSTS:
                return False, f"target host not in allowlist: {host}"

        if not ALLOW_LOCALHOST_TARGETS and host in {"localhost", "127.0.0.1", "::1"}:
            return False, f"localhost target blocked: {host}"

        if not ALLOW_PRIVATE_HOSTS and host_is_private_or_local(host):
            return False, f"private/local target blocked: {host}"

        return True, "allowed"

    except Exception as e:
        return False, f"target validation error: {e}"

def load_program_scope_policies():
    loaded = safe_json_loads(PROGRAM_SCOPE_POLICIES_JSON)
    if isinstance(loaded, dict):
        return loaded
    return {}


def program_scope_policy(program: str):
    policies = load_program_scope_policies()
    policy = policies.get(program, {})
    if not isinstance(policy, dict):
        policy = {}

    allowed_hosts = policy.get("allowed_hosts")
    if not isinstance(allowed_hosts, list):
        allowed_hosts = None
    else:
        allowed_hosts = [str(h).strip().lower() for h in allowed_hosts if str(h).strip()]

    allow_private_hosts = policy.get("allow_private_hosts")
    if not isinstance(allow_private_hosts, bool):
        allow_private_hosts = None

    allow_localhost_targets = policy.get("allow_localhost_targets")
    if not isinstance(allow_localhost_targets, bool):
        allow_localhost_targets = None

    return {
        "allowed_hosts": allowed_hosts,
        "allow_private_hosts": allow_private_hosts,
        "allow_localhost_targets": allow_localhost_targets,
    }


def target_host_allowed_for_program(url: str, program: str):
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()

        if scheme not in {"http", "https"}:
            return False, f"disallowed URL scheme: {scheme or 'missing'}"

        if not host:
            return False, "missing target host"

        policy = program_scope_policy(program)

        effective_allowed_hosts = policy["allowed_hosts"] if policy["allowed_hosts"] is not None else ALLOWED_TARGET_HOSTS
        effective_allow_private = policy["allow_private_hosts"] if policy["allow_private_hosts"] is not None else ALLOW_PRIVATE_HOSTS
        effective_allow_localhost = policy["allow_localhost_targets"] if policy["allow_localhost_targets"] is not None else ALLOW_LOCALHOST_TARGETS

        if effective_allowed_hosts:
            if host not in effective_allowed_hosts:
                return False, f"target host not in allowlist for program {program}: {host}"

        if not effective_allow_localhost and host in {"localhost", "127.0.0.1", "::1"}:
            return False, f"localhost target blocked for program {program}: {host}"

        if not effective_allow_private and host_is_private_or_local(host):
            return False, f"private/local target blocked for program {program}: {host}"

        return True, "allowed"

    except Exception as e:
        return False, f"target validation error: {e}"

def new_trace_id() -> str:
    return uuid.uuid4().hex[:12]


def log_event(level: str, trace_id: str, event: str, **kwargs):
    payload = {
        "trace_id": trace_id,
        "event": event,
        **kwargs
    }

    line = json.dumps(payload, default=str)

    if level.lower() == "debug":
        logger.debug(line)
    elif level.lower() == "warning":
        logger.warning(line)
    elif level.lower() == "error":
        logger.error(line)
    else:
        logger.info(line)

def now_ms() -> float:
    return time.perf_counter() * 1000.0


def elapsed_ms(start_ms: float) -> float:
    return round(now_ms() - start_ms, 2)

def make_json_safe(obj):
    if isinstance(obj, dict):
        return {str(k): make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    elif isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    else:
        return str(obj)

def query_name_is_noise(name: str) -> bool:
    return (name or "").strip().lower() in GENERIC_NOISE_QUERY_NAMES


def candidate_input_is_meaningful(item: dict) -> bool:
    classification = item.get("classification", "generic")
    name = (item.get("name") or "").strip().lower()
    source = item.get("source", "")

    if classification in {"id-like", "identity", "role"}:
        return True

    if source == "query" and query_name_is_noise(name):
        return False

    if source == "path" and classification == "id-like":
        return True

    return False


def meaningful_candidate_inputs(candidate_inputs: list[dict]):
    return [p for p in candidate_inputs if candidate_input_is_meaningful(p)]


def should_attempt_auto_replay(method: str, url: str, candidate_inputs: list[dict]) -> bool:
    method = (method or "").upper()
    path = extract_path(url)

    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
        return False

    if is_business_path(path):
        return True

    meaningful = meaningful_candidate_inputs(candidate_inputs)
    if meaningful:
        return True

    if is_id_like_path(path):
        return True

    return False

# ============================================
# ENDPOINT INTELLIGENCE GRAPH
# ============================================

def normalize_path_for_graph(path: str) -> str:
    """
    Turn concrete paths into graph-friendly shapes.
    Example:
      /rest/basket/3 -> /rest/basket/{id}
      /api/Address/7 -> /api/Address/{id}
    """
    parts = [p for p in path.split("/") if p]
    normalized = []

    for p in parts:
        if p.isdigit() or is_hash_like_segment(p):
            normalized.append("{id}")
        else:
            normalized.append(p)

    return "/" + "/".join(normalized)


def extract_path_object_tokens(path: str):
    """
    Extract object-like tokens from a path for graph linking.
    Example:
      /rest/basket/3/checkout -> ["basket:3"]
      /api/Address/7 -> ["address:7"]
    """
    parts = [p for p in path.split("/") if p]
    tokens = []

    for i, part in enumerate(parts):
        if part.isdigit() and i > 0:
            parent = parts[i - 1].strip().lower()
            if parent:
                tokens.append(f"{parent}:{part}")
        elif is_hash_like_segment(part) and i > 0:
            parent = parts[i - 1].strip().lower()
            if parent:
                tokens.append(f"{parent}:{part}")

    return tokens


def graph_node_id(method: str, path: str) -> str:
    return f"{method.upper()} {normalize_path_for_graph(path)}"


def graph_related_nodes(candidate_inputs: list[dict], path: str):
    """
    Build lightweight graph clues from candidate inputs and path objects.
    """
    related = []

    for token in extract_path_object_tokens(path):
        related.append({
            "kind": "path-object",
            "token": token
        })

    for item in candidate_inputs:
        if item.get("classification") == "id-like":
            related.append({
                "kind": "input-object",
                "token": f"{item.get('name')}={item.get('sample_value')}",
                "source": item.get("source")
            })

        elif item.get("classification") == "identity":
            related.append({
                "kind": "identity",
                "token": f"{item.get('name')}={item.get('sample_value')}",
                "source": item.get("source")
            })

        elif item.get("classification") == "role":
            related.append({
                "kind": "role",
                "token": f"{item.get('name')}={item.get('sample_value')}",
                "source": item.get("source")
            })

    return related


def endpoint_intelligence_graph(path: str, method: str, candidate_inputs: list[dict], history: list[dict], signals: list[dict]):
    """
    Build a compact graph summary for the current endpoint.
    This is the first graph layer: node identity + object relations + local history clues.
    """
    node = graph_node_id(method, path)
    normalized_path = normalize_path_for_graph(path)
    related = graph_related_nodes(candidate_inputs, path)

    signal_types = [s.get("type", "") for s in signals]
    prior_statuses = sorted(list({h["status_code"] for h in history})) if history else []
    prior_auth_states = sorted(list({h["auth_state"] for h in history})) if history else []

    graph = {
        "node_id": node,
        "normalized_path": normalized_path,
        "path_objects": extract_path_object_tokens(path),
        "related_tokens": related,
        "history_statuses": prior_statuses,
        "history_auth_states": prior_auth_states,
        "signal_types": signal_types
    }

    return graph


def endpoint_graph_hints(graph: dict):
    hints = []

    if graph.get("path_objects"):
        hints.append("Path contains object-like resource references that may link to related endpoints.")

    if any(t.get("kind") == "identity" for t in graph.get("related_tokens", [])):
        hints.append("Identity-like inputs appear and may reveal ownership binding logic.")

    if any(t.get("kind") == "role" for t in graph.get("related_tokens", [])):
        hints.append("Role-like inputs may influence privilege boundaries.")

    if "multi-auth-diff" in graph.get("signal_types", []):
        hints.append("Auth-sensitive behavior detected — compare across users.")

    # 🔥 MEMORY-AWARE PART
    node_mem = graph.get("persistent_node_memory")
    edge_mem = graph.get("persistent_edge_memory", [])
    auth_mem = graph.get("persistent_auth_memory", [])

    if node_mem and int(node_mem.get("times_seen", 0)) >= 3:
        hints.append(f"This endpoint family has been seen {node_mem.get('times_seen')} times — likely important attack surface.")

    if edge_mem:
        hints.append("Recurring object relationships detected — strong pivot opportunity.")

    if auth_mem and len(auth_mem) > 1:
        hints.append("Multiple auth states observed historically — high chance of access control inconsistencies.")

    return hints

# ============================================
# PERSISTENT ENDPOINT GRAPH MEMORY
# ============================================

def save_graph_node(program: str, graph: dict, method: str, path: str):
    conn = get_db()
    now = utc_now_iso()

    conn.execute("""
        INSERT INTO endpoint_graph_nodes (
            program, node_id, normalized_path, method, last_path, last_seen_at, times_seen
        )
        VALUES (?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(program, node_id)
        DO UPDATE SET
            normalized_path=excluded.normalized_path,
            method=excluded.method,
            last_path=excluded.last_path,
            last_seen_at=excluded.last_seen_at,
            times_seen=endpoint_graph_nodes.times_seen + 1
    """, (
        program,
        graph["node_id"],
        graph["normalized_path"],
        method,
        path,
        now
    ))

    conn.commit()
    conn.close()


def save_graph_auth_pattern(program: str, graph: dict, auth_state: str):
    conn = get_db()
    now = utc_now_iso()

    conn.execute("""
        INSERT INTO endpoint_graph_auth_patterns (
            program, node_id, auth_state, first_seen_at, last_seen_at, times_seen
        )
        VALUES (?, ?, ?, ?, ?, 1)
        ON CONFLICT(program, node_id, auth_state)
        DO UPDATE SET
            last_seen_at=excluded.last_seen_at,
            times_seen=endpoint_graph_auth_patterns.times_seen + 1
    """, (
        program,
        graph["node_id"],
        auth_state,
        now,
        now
    ))

    conn.commit()
    conn.close()


def save_graph_edges(program: str, graph: dict):
    conn = get_db()
    now = utc_now_iso()

    for token_info in graph.get("related_tokens", []):
        edge_kind = token_info.get("kind", "related")
        to_token = token_info.get("token", "")
        if not to_token:
            continue

        conn.execute("""
            INSERT INTO endpoint_graph_edges (
                program, from_node, to_token, edge_kind, first_seen_at, last_seen_at, times_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(program, from_node, to_token, edge_kind)
            DO UPDATE SET
                last_seen_at=excluded.last_seen_at,
                times_seen=endpoint_graph_edges.times_seen + 1
        """, (
            program,
            graph["node_id"],
            to_token,
            edge_kind,
            now,
            now
        ))

    conn.commit()
    conn.close()


def load_graph_node_memory(program: str, node_id: str):
    conn = get_db()
    row = conn.execute("""
        SELECT *
        FROM endpoint_graph_nodes
        WHERE program = ? AND node_id = ?
        LIMIT 1
    """, (program, node_id)).fetchone()
    conn.close()

    return dict(row) if row else None


def load_graph_edge_memory(program: str, node_id: str):
    conn = get_db()
    rows = conn.execute("""
        SELECT to_token, edge_kind, times_seen, last_seen_at
        FROM endpoint_graph_edges
        WHERE program = ? AND from_node = ?
        ORDER BY times_seen DESC, last_seen_at DESC
        LIMIT 30
    """, (program, node_id)).fetchall()
    conn.close()

    return [dict(r) for r in rows]


def load_graph_auth_memory(program: str, node_id: str):
    conn = get_db()
    rows = conn.execute("""
        SELECT auth_state, times_seen, last_seen_at
        FROM endpoint_graph_auth_patterns
        WHERE program = ? AND node_id = ?
        ORDER BY times_seen DESC, last_seen_at DESC
    """, (program, node_id)).fetchall()
    conn.close()

    return [dict(r) for r in rows]


def persist_endpoint_graph_memory(program: str, method: str, path: str, auth_state: str, graph: dict):
    save_graph_node(program, graph, method, path)
    save_graph_auth_pattern(program, graph, auth_state)
    save_graph_edges(program, graph)


# ============================================
# PERSISTENT GRAPH MEMORY ENRICHMENT
# ============================================

def enrich_graph_with_persistent_memory(program: str, graph: dict):
    node_memory = load_graph_node_memory(program, graph["node_id"])
    edge_memory = load_graph_edge_memory(program, graph["node_id"])
    auth_memory = load_graph_auth_memory(program, graph["node_id"])

    enriched = dict(graph)
    enriched["persistent_node_memory"] = node_memory
    enriched["persistent_edge_memory"] = edge_memory
    enriched["persistent_auth_memory"] = auth_memory

    return enriched


def augment_signals_with_persistent_graph_memory(signals: list[dict], graph: dict):
    augmented = list(signals)

    node_memory = graph.get("persistent_node_memory")
    edge_memory = graph.get("persistent_edge_memory", [])
    auth_memory = graph.get("persistent_auth_memory", [])

    if node_memory:
        times_seen = int(node_memory.get("times_seen", 0))
        if times_seen >= 3:
            augmented.append({
                "type": "graph-node-recurrence",
                "severity": "medium",
                "detail": f"Endpoint graph node has been seen {times_seen} times historically"
            })

    if edge_memory:
        recurring_edges = [e for e in edge_memory if int(e.get("times_seen", 0)) >= 2]
        if recurring_edges:
            augmented.append({
                "type": "graph-recurring-object-links",
                "severity": "medium",
                "detail": f"{len(recurring_edges)} recurring object/link relationships found in persistent graph memory"
            })

    if auth_memory:
        auth_states = [a.get("auth_state", "") for a in auth_memory]
        if len(set(auth_states)) > 1:
            augmented.append({
                "type": "graph-auth-diversity",
                "severity": "medium",
                "detail": "Persistent graph memory shows this endpoint family under multiple auth states"
            })

    return augmented


def augment_exploit_suggestions_with_persistent_graph_memory(suggestions: list[dict], graph: dict):
    out = list(suggestions)

    node_memory = graph.get("persistent_node_memory")
    edge_memory = graph.get("persistent_edge_memory", [])
    auth_memory = graph.get("persistent_auth_memory", [])

    if node_memory:
        out.append({
            "title": "Persistent node history review",
            "priority": "medium",
            "category": "graph-memory",
            "why": "This endpoint node has persisted historical graph memory and may represent a repeatedly observed attack surface.",
            "checks": [
                f"Times seen in graph memory: {node_memory.get('times_seen', 0)}",
                f"Last concrete path seen: {node_memory.get('last_path', 'N/A')}",
                "Check whether repeated observations reveal stable but weak authorization behavior."
            ]
        })

    if edge_memory:
        top_edges = [
            f"{e.get('edge_kind')}::{e.get('to_token')} (seen {e.get('times_seen', 0)} times)"
            for e in edge_memory[:6]
        ]
        out.append({
            "title": "Persistent object-link pivoting",
            "priority": "medium",
            "category": "graph-memory",
            "why": "Persistent graph edges show recurring object relationships that may help pivot testing.",
            "checks": [
                "Pivot through the most recurring linked objects and compare behavior across related routes.",
                "Look for inconsistent validation between path-linked and body-linked objects.",
                "Recurring links: " + "; ".join(top_edges)
            ]
        })

    if auth_memory:
        auth_labels = [
            f"{a.get('auth_state')} (seen {a.get('times_seen', 0)} times)"
            for a in auth_memory[:6]
        ]
        out.append({
            "title": "Persistent auth-state comparison",
            "priority": "medium",
            "category": "graph-auth-memory",
            "why": "Persistent memory shows multiple auth-state observations for this endpoint node.",
            "checks": [
                "Review whether object access differs depending on auth mechanism or session state.",
                "Compare response differences across the auth states already seen historically.",
                "Auth memory: " + "; ".join(auth_labels)
            ]
        })

    return out

# ============================================
# ATTACK CHAIN ENGINE
# ============================================

def chain_stage_label(signal_types: list[str], normalized_path: str):
    """
    Heuristic stage labeling for endpoints.
    Stronger routing for exploit-flow reasoning.
    """
    p = (normalized_path or "").lower()

    action_terms = [
        "checkout", "payment", "wallet", "redeem", "apply", "submit",
        "cancel", "delete", "update", "change", "transfer", "purchase"
    ]
    identity_terms = [
        "address", "profile", "account", "user", "customer", "wallet"
    ]
    discovery_terms = [
        "search", "list", "products", "items", "catalog", "browse"
    ]

    if any(term in p for term in action_terms):
        return "action"

    if any(term in p for term in identity_terms) and "{id}" in p:
        return "identity-resource"

    if "{id}" in p:
        return "object-access"

    if any(term in p for term in discovery_terms):
        return "discovery"

    if (
        "multi-auth-high-confidence-idor" in signal_types
        or "high-probability-idor" in signal_types
        or "multi-auth-same-object-difference" in signal_types
        or "cross-user-corroborated-object-access" in signal_types
    ):
        return "object-access"

    return "general"

def chain_neighbor_score(target: str, reason: str = "") -> int:
    """
    Score likely pivot quality for attack-chain neighbors.
    """
    t = (target or "").lower()
    r = (reason or "").lower()

    score = 0

    if "{id}" in t:
        score += 8

    if any(x in t for x in ["/checkout", "/payment", "/wallet", "/order", "/address", "/profile"]):
        score += 10

    if any(x in t for x in ["/search", "/products", "/items", "/list"]):
        score += 4

    if "same-normalized-shape" in r:
        score += 8

    if "shared-resource-family" in r:
        score += 6

    if t.startswith("/rest/") or t.startswith("/api/"):
        score += 4

    if "history" in t or "details" in t:
        score += 2

    return score

def build_attack_chain_seed(path: str, method: str, graph: dict, signals: list[dict], suggestions: list[dict]):
    """
    Build a compact seed object that can be chained to related endpoints.
    """
    signal_types = [s.get("type", "") for s in signals]
    stage = chain_stage_label(signal_types, graph.get("normalized_path", path))

    families = graph_object_families(graph)
    suggestion_titles = [s.get("title", "") for s in suggestions]

    return {
        "node_id": graph.get("node_id"),
        "normalized_path": graph.get("normalized_path", path),
        "method": method,
        "stage": stage,
        "families": families,
        "signal_types": signal_types,
        "suggestion_titles": suggestion_titles
    }


def attack_chain_neighbors(seed: dict, graph: dict, related_history: list[dict]):
    """
    Propose and rank neighboring steps based on graph patterns + historical related endpoints.
    """
    neighbors = []

    patterns = graph_related_endpoint_patterns(graph)

    for p in patterns:
        neighbors.append({
            "kind": "pattern-neighbor",
            "target": p,
            "reason": "pattern-derived",
            "score": chain_neighbor_score(p, "pattern-derived")
        })

    for item in related_history:
        target = f"{item.get('method')} {item.get('path')}"
        reason = item.get("reason", "")
        neighbors.append({
            "kind": "historical-neighbor",
            "target": target,
            "reason": reason,
            "score": chain_neighbor_score(target, reason)
        })

    deduped = []
    seen = set()

    for n in neighbors:
        key = (n.get("kind"), n.get("target"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(n)

    deduped.sort(key=lambda x: int(x.get("score", 0)), reverse=True)

    return deduped[:15]

def build_attack_chain(seed: dict, graph: dict, related_history: list[dict]):
    """
    Build a ranked first-pass attack chain around the current endpoint.
    """
    stage = seed.get("stage", "general")
    families = seed.get("families", [])
    neighbors = attack_chain_neighbors(seed, graph, related_history)

    chain = {
        "seed": seed,
        "neighbors": neighbors,
        "chain_hypotheses": []
    }

    high_value_neighbors = [n.get("target", "") for n in neighbors[:6]]

    if stage == "object-access":
        chain["chain_hypotheses"].append({
            "name": "Object Access To Action Flow",
            "steps": [
                "Validate whether object identifiers can access another user's resource.",
                "Pivot the same identifier into adjacent action endpoints such as checkout, payment, update, or delete.",
                "Check whether action endpoints enforce ownership more weakly than read endpoints."
            ]
        })

    if stage == "identity-resource":
        chain["chain_hypotheses"].append({
            "name": "Identity To Resource Pivot",
            "steps": [
                "Inspect identity-linked resources such as profile, address, wallet, or account objects.",
                "Pivot recovered identifiers into related object-family endpoints.",
                "Check whether identity-linked data can be reused or replayed across other sessions or users."
            ]
        })

    if stage == "discovery":
        chain["chain_hypotheses"].append({
            "name": "Discovery To Object To Action",
            "steps": [
                "Use discovery endpoints to enumerate valid object references.",
                "Replay discovered identifiers into direct object endpoints.",
                "Test whether downstream action/workflow routes accept those references without strict ownership validation."
            ]
        })

    if families:
        chain["chain_hypotheses"].append({
            "name": "Family Pivot Chain",
            "steps": [
                "Track the same object family across multiple endpoints.",
                "Compare path-based and body-based references for the same family.",
                "Look for inconsistent authorization across read, edit, workflow, and delete flows."
            ]
        })

    if high_value_neighbors:
        chain["chain_hypotheses"].append({
            "name": "Ranked Neighbor Pivoting",
            "steps": [
                "Prioritize the highest-ranked related endpoints first.",
                "Carry the same object reference across those pivots.",
                "Capture where authorization behavior changes while the underlying object stays constant."
            ]
        })

    return chain

def attack_chain_hints(chain: dict):
    """
    Convert attack chain structure into concise, high-signal hints.
    """
    hints = []

    seed = chain.get("seed", {})
    stage = seed.get("stage", "general")
    families = seed.get("families", [])
    neighbors = chain.get("neighbors", [])

    hints.append(f"Current endpoint stage: {stage}")

    if families:
        hints.append("Likely object families in chain: " + ", ".join(families))

    if neighbors:
        previews = []
        for n in neighbors[:6]:
            target = n.get("target", "")
            score = n.get("score", 0)
            previews.append(f"{target} [score={score}]")
        hints.append("Top ranked pivots: " + ", ".join(previews))

    hypotheses = chain.get("chain_hypotheses", [])
    if hypotheses:
        hints.append(
            "Attack chain hypotheses available: " +
            ", ".join(h.get("name", "") for h in hypotheses)
        )

    return hints

# ============================================
# ATTACK CHAIN ENRICHMENT
# ============================================

def augment_signals_with_attack_chain(signals: list[dict], chain: dict):
    augmented = list(signals)

    seed = chain.get("seed", {})
    neighbors = chain.get("neighbors", [])
    hypotheses = chain.get("chain_hypotheses", [])

    stage = seed.get("stage", "general")
    if stage != "general":
        augmented.append({
            "type": "attack-chain-stage",
            "severity": "medium",
            "detail": f"Endpoint classified as chain stage: {stage}"
        })

    if neighbors:
        augmented.append({
            "type": "attack-chain-neighbors",
            "severity": "medium",
            "detail": f"{len(neighbors)} likely next pivot endpoint(s) identified"
        })

    if hypotheses:
        augmented.append({
            "type": "attack-chain-hypotheses",
            "severity": "medium",
            "detail": f"{len(hypotheses)} attack-chain hypothesis/hypotheses generated"
        })

    return augmented


def augment_exploit_suggestions_with_attack_chain(suggestions: list[dict], chain: dict):
    out = list(suggestions)

    hints = attack_chain_hints(chain)
    hypotheses = chain.get("chain_hypotheses", [])
    neighbors = chain.get("neighbors", [])

    if hints:
        out.append({
            "title": "Attack chain overview",
            "priority": "medium",
            "category": "attack-chain",
            "why": "The current endpoint appears to fit into a broader exploitation flow rather than a single isolated check.",
            "checks": hints
        })

    if hypotheses:
        formatted = []
        for h in hypotheses[:4]:
            steps = h.get("steps", [])
            formatted.append(
                h.get("name", "Unnamed Chain") + ": " + " -> ".join(steps[:3])
            )

        out.append({
            "title": "Attack chain hypotheses",
            "priority": "high",
            "category": "attack-flow",
            "why": "The system generated possible multi-step exploitation paths based on endpoint stage and object family relationships.",
            "checks": formatted
        })

    if neighbors:
        labels = []
        for n in neighbors[:8]:
            target = n.get("target", "")
            reason = n.get("reason", "")
            if reason:
                labels.append(f"{target} ({reason})")
            else:
                labels.append(target)

        out.append({
            "title": "Next pivot endpoints",
            "priority": "medium",
            "category": "pivoting",
            "why": "Related endpoints may form the next step in an authorization or workflow abuse chain.",
            "checks": labels
        })

    return out

# ============================================
# ENDPOINT GRAPH MATCHING / FLOW HELPERS
# ============================================

def graph_object_families(graph: dict):
    """
    Return coarse resource families seen in the endpoint graph.
    Example:
      basket:3 -> basket
      address:7 -> address

    Important:
    - strip helper suffixes like _path
    - avoid empty/generic junk families
    - do not treat technical helper names as business objects
    """
    families = set()

    ignored_exact = {
        "",
        "id",
        "path",
        "segment",
        "query",
        "json",
        "form"
    }

    def normalize_family_name(name: str) -> str:
        raw = str(name or "").strip().lower()
        if not raw:
            return ""

        # Remove common helper suffixes introduced by input extraction
        for suffix in ("_path", "_query", "_json", "_form"):
            if raw.endswith(suffix):
                raw = raw[: -len(suffix)]

        # Remove common ID endings
        if raw.endswith("_id"):
            raw = raw[:-3]
        elif raw.endswith("id") and len(raw) > 2:
            raw = raw[:-2]

        raw = raw.strip("_- ")

        if raw in ignored_exact:
            return ""

        # Avoid obviously synthetic segment names
        if raw.startswith("segment_"):
            return ""

        return raw

    for token in graph.get("path_objects", []):
        if ":" in token:
            fam = normalize_family_name(token.split(":", 1)[0])
            if fam:
                families.add(fam)

    for token_info in graph.get("related_tokens", []):
        token = token_info.get("token", "")
        if "=" in token:
            left = token.split("=", 1)[0].strip().lower()
            fam = normalize_family_name(left)
            if fam:
                families.add(fam)

    return sorted(families)

def graph_related_endpoint_patterns(graph: dict, max_patterns: int = 10):
    """
    Generate related endpoint patterns from observed graph data.
    Uses persistent node memory and family inference, but only for families
    that have actually been seen in historical observations.
    """
    patterns = set()

    # 1. Use real observed path from persistent memory (if available)
    node_mem = graph.get("persistent_node_memory")
    if node_mem and node_mem.get("last_path"):
        real_path = node_mem["last_path"]
        # Normalize numeric IDs → {id}
        clean = re.sub(r"/\d+(/|$)", r"/{id}\1", real_path)
        # Normalize UUIDs → {id}
        clean = re.sub(r"/[0-9a-fA-F-]{8,}(/|$)", r"/{id}\1", clean)
        patterns.add(clean)

        # Extract the prefix (e.g., /rest or /api) from the real path
        prefix_match = re.match(r"^(/rest|/api)(/|$)", real_path)
        prefix = prefix_match.group(1) if prefix_match else ""

        # 2. Derive family-based patterns ONLY for families that have been observed
        if prefix:
            # Get families that actually appear in persistent edge memory (real observations)
            observed_families = set()
            for edge in graph.get("persistent_edge_memory", []):
                token = edge.get("to_token", "")
                if ":" in token:
                    fam = token.split(":", 1)[0].strip().lower()
                    if fam and len(fam) >= 3:
                        observed_families.add(fam)
                elif "=" in token:
                    left = token.split("=", 1)[0].strip().lower()
                    # Remove suffixes like _path
                    for suffix in ("_path", "_query", "_json", "_form"):
                        if left.endswith(suffix):
                            left = left[:-len(suffix)]
                    if left and len(left) >= 3:
                        observed_families.add(left)

            # Only add patterns for families that have been seen historically
            for fam in observed_families:
                patterns.add(f"{prefix}/{fam}")
                patterns.add(f"{prefix}/{fam}/{{id}}")

    # 3. Smart filtering
    filtered = []
    for p in patterns:
        if not p.startswith("/"):
            continue
        if any(x in p.lower() for x in ["undefined", "null", "test", "debug", "nan"]):
            continue
        if p.count("{id}") > 2:
            continue
        filtered.append(p)

    # 4. Rank by depth and ID presence
    def score(p):
        s = p.count("/")
        if "{id}" in p:
            s += 2
        return s

    filtered = sorted(set(filtered), key=score, reverse=True)
    return filtered[:max_patterns]

def graph_history_similarity(current_path: str, current_method: str, program: str = "local-lab"):
    """
    Look for historically seen endpoints whose normalized path shape matches
    or is closely related to the current one.
    """
    conn = get_db()
    rows = conn.execute("""
        SELECT path, method, COUNT(*) as hits
        FROM observations
        WHERE program = ?
        GROUP BY path, method
        ORDER BY hits DESC
        LIMIT 200
    """, (program,)).fetchall()
    conn.close()

    current_norm = normalize_path_for_graph(current_path)
    related = []

    for row in rows:
        path = row["path"]
        method = row["method"]
        hits = row["hits"]
        norm = normalize_path_for_graph(path)

        if path == current_path and method == current_method:
            continue

        # same normalized family
        if norm == current_norm:
            related.append({
                "path": path,
                "method": method,
                "hits": hits,
                "reason": "same-normalized-shape"
            })
            continue

        # shared leading family chunk
        current_parts = [p for p in current_norm.split("/") if p]
        other_parts = [p for p in norm.split("/") if p]
        if current_parts and other_parts and current_parts[:2] == other_parts[:2]:
            related.append({
                "path": path,
                "method": method,
                "hits": hits,
                "reason": "shared-resource-family"
            })

    return related[:10]

# ============================================
# GRAPH-AWARE SIGNAL ENRICHMENT
# ============================================

def augment_signals_with_graph(signals: list[dict], graph: dict, related_history: list[dict]):
    augmented = list(signals)

    graph_hints = endpoint_graph_hints(graph)
    families = graph_object_families(graph)

    if families:
        augmented.append({
            "type": "graph-object-family",
            "severity": "medium",
            "detail": "Endpoint is linked to object families: " + ", ".join(families)
        })

    if related_history:
        augmented.append({
            "type": "graph-related-endpoints",
            "severity": "medium",
            "detail": f"{len(related_history)} historically seen related endpoint(s) found in the same family"
        })

    if graph_hints:
        augmented.append({
            "type": "graph-flow-hints",
            "severity": "medium",
            "detail": " | ".join(graph_hints[:3])
        })

    return augmented

# ============================================
# GRAPH-AWARE EXPLOIT SUGGESTION ENRICHMENT
# ============================================

def augment_exploit_suggestions_with_graph(suggestions: list[dict], graph: dict, related_history: list[dict]):
    out = list(suggestions)

    patterns = graph_related_endpoint_patterns(graph)
    families = graph_object_families(graph)

    if patterns:
        out.append({
            "title": "Related endpoint family review",
            "priority": "medium",
            "category": "endpoint-graph",
            "why": "The endpoint graph suggests related resource routes that may share object authorization logic.",
            "checks": [
                "Compare behavior across related endpoint families that touch the same object type.",
                "Look for inconsistent authorization between read, detail, and workflow endpoints.",
                "Related patterns: " + ", ".join(patterns[:8])
            ]
        })

    if related_history:
        related_labels = [f"{r['method']} {r['path']} ({r['reason']})" for r in related_history[:6]]
        out.append({
            "title": "Historical related endpoint comparison",
            "priority": "medium",
            "category": "history-graph",
            "why": "Historically observed endpoints appear related by normalized shape or resource family.",
            "checks": [
                "Review whether related endpoints expose different auth or object-validation behavior.",
                "Check if workflow endpoints enforce ownership differently from read-only endpoints.",
                "Related history: " + "; ".join(related_labels)
            ]
        })

    if families:
        out.append({
            "title": "Object family pivoting",
            "priority": "medium",
            "category": "graph-pivot",
            "why": "The current request belongs to one or more object families that may connect to broader business flows.",
            "checks": [
                "Pivot testing across endpoints that mention the same object families.",
                "Compare identifiers passed in path versus JSON body for the same family.",
                "Object families: " + ", ".join(families)
            ]
        })

    return out


# ============================================
# CANDIDATE INPUT EXTRACTION
# ============================================

def classify_params_from_query(query: str):
    parsed = parse_qs(query, keep_blank_values=True)
    results = []

    for k, values in parsed.items():
        sample = values[0] if values else ""
        results.append({
            "name": k,
            "value": sample,
            "sample_value": str(sample),
            "source": "query",
            "value_type": infer_value_type(sample),
            "classification": classify_param(k, sample)
        })

    return results


def classify_params_from_body(body: str, headers: dict):
    results = []
    content_type = str(headers.get("Content-Type", headers.get("content-type", ""))).lower()

    if not body:
        return results

    if "application/json" in content_type or looks_like_json(body):
        loaded = safe_json_loads(body)
        if loaded is not None:
            for k, v in flatten_json(loaded):
                results.append({
                    "name": k,
                    "value": v,
                    "sample_value": str(v),
                    "source": "json",
                    "value_type": infer_value_type(v),
                    "classification": classify_param(k, v)
                })
            return results

    if "application/x-www-form-urlencoded" in content_type:
        parsed = parse_qs(body, keep_blank_values=True)
        for k, values in parsed.items():
            sample = values[0] if values else ""
            results.append({
                "name": k,
                "value": sample,
                "sample_value": str(sample),
                "source": "form",
                "value_type": infer_value_type(sample),
                "classification": classify_param(k, sample)
            })

    return results


def path_segment_name(segments: list[str], index: int) -> str:
    if index > 0:
        base = segments[index - 1].strip().lower()
        if base:
            return f"{base}_path"
    return f"segment_{index}"


def extract_path_params(path: str):
    segments = [s for s in path.strip("/").split("/") if s]
    results = []

    for i, seg in enumerate(segments):
        if seg.isdigit():
            results.append({
                "name": path_segment_name(segments, i),
                "value": seg,
                "sample_value": seg,
                "source": "path",
                "value_type": "string-numeric",
                "classification": "id-like",
                "path_segment_index": i,
                "segment_kind": "numeric_id"
            })
        elif is_hash_like_segment(seg):
            results.append({
                "name": path_segment_name(segments, i),
                "value": seg,
                "sample_value": seg,
                "source": "path",
                "value_type": "string",
                "classification": "id-like",
                "path_segment_index": i,
                "segment_kind": "hash_like_id"
            })

    return results


def extract_candidate_inputs(url: str, headers: dict, body: str):
    query_items = classify_params_from_query(extract_query(url))
    body_items = classify_params_from_body(body, headers)
    path_items = extract_path_params(extract_path(url))

    seen = set()
    merged = []

    for item in query_items + body_items + path_items:
        key = (item.get("name"), item.get("source"), item.get("sample_value"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)

    return merged

# ============================================
# MUTATION PRESETS
# ============================================

def mutation_presets_for_input(item: dict):
    source = item.get("source")
    value = str(item.get("value", ""))
    classification = item.get("classification", "generic")
    kind = item.get("segment_kind", "")

    presets = []

    if classification == "id-like":
        if source == "path" and kind == "numeric_id":
            try:
                n = int(value)
                candidates = [n - 1, n + 1, n + 2, 0, 1, 10 if n != 10 else 11]
                deduped = []
                for c in candidates:
                    if c < 0:
                        continue
                    if c not in deduped:
                        deduped.append(c)
                presets = [str(x) for x in deduped]
            except Exception:
                presets = ["0", "1", "2"]

        elif value.isdigit():
            try:
                n = int(value)
                candidates = [n - 1, n + 1, n + 2, 0, 1]
                deduped = []
                for c in candidates:
                    if c < 0:
                        continue
                    if c not in deduped:
                        deduped.append(c)
                presets = [str(x) for x in deduped]
            except Exception:
                presets = ["0", "1", "2"]
        else:
            if len(value) >= 8:
                presets = [
                    value[: max(1, len(value) // 2)],
                    "0" * len(value),
                    "A" * len(value)
                ]

    elif classification == "role":
        presets = ["user", "admin", "moderator", "", "null"]

    elif classification == "identity":
        presets = ["test@example.com", "other@example.com", "", "null"]

    elif source in ("json", "form", "query"):
        presets = ["", "0", "1", "null", "true", "false"]

    deduped = []
    for p in presets:
        if p not in deduped and str(p) != value:
            deduped.append(str(p))

    return deduped[:8]

# ============================================
# HISTORY / STORAGE
# ============================================

def load_history(path: str, method: str, program: str = "local-lab"):
    conn = get_db()
    rows = conn.execute(
        """
        SELECT * FROM observations
        WHERE path=? AND method=? AND program=?
        ORDER BY id ASC
        """,
        (path, method, program)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_observation(program: str, method: str, path: str, query: str, status_code: int, response_length: int, auth_state: str, fingerprint_value: str):
    conn = get_db()
    conn.execute(
        """
        INSERT INTO observations (
            program, method, path, query, status_code, response_length, auth_state, fingerprint, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (program, method, path, query, status_code, response_length, auth_state, fingerprint_value, utc_now_iso())
    )
    conn.commit()
    conn.close()

# ============================================
# REQUEST EXECUTION
# ============================================

def perform_request(method: str, url: str, headers: dict, body: str, strip_auth: bool = False, timeout: int = 10, program: str = "local-lab"):
    allowed, reason = target_host_allowed_for_program(url, program)
    if not allowed:
        raise ValueError(f"Blocked replay target: {reason}")

    session = get_http_session()

    replay_headers = dict(headers or {})
    replay_headers.pop("X-API-Key", None)

    if strip_auth:
        replay_headers.pop("Authorization", None)
        replay_headers.pop("authorization", None)
        replay_headers.pop("Cookie", None)
        replay_headers.pop("cookie", None)

    try:
        resp = session.request(
            method=method,
            url=url,
            headers=replay_headers,
            data=body if body else None,
            timeout=timeout
        )

        return {
            "status_code": resp.status_code,
            "length": len(resp.text),
            "fingerprint": stable_fingerprint(resp.text),
            "raw_fingerprint": fp(resp.text),
            "body": resp.text,
            "fields": response_json_fields(resp.text),
            "normalized_fields": normalized_response_fields(resp.text)
        }
    except Exception as e:
        raise RuntimeError(f"request execution failed for {method} {url}: {e}") from e

def auto_replay(url: str, method: str, headers: dict, body: str, program: str = "local-lab"):
    try:
        result = perform_request(method, url, headers, body, strip_auth=True, timeout=10, program=program)
        return {
            "performed": True,
            "status_code": result["status_code"],
            "length": result["length"],
            "fingerprint": result["fingerprint"]
        }
    except Exception as e:
        err = str(e)
        return {
            "performed": False,
            "error": err,
            "error_kind": replay_error_kind(err)
        }

# ============================================
# EXPLOIT CONFIRMATION
# ============================================

def exploit_confirmation(base: dict, mutated: dict, input_name: str, original_value: str, new_value: str):
    base_status = int(base.get("status_code", 0) or 0)
    mut_status = int(mutated.get("status_code", 0) or 0)

    base_fields = base.get("normalized_fields", base.get("fields", {}))
    mut_fields = mutated.get("normalized_fields", mutated.get("fields", {}))
    field_diff = diff_response_fields(base_fields, mut_fields)

    score = 0
    reasons = []

    auth_boundary_only = False
    successful_cross_object_behavior = False
    sensitive_disclosure_signal = False
    ownership_signal = False
    public_resource_context = False
    is_empty_response = False
    user_id_changed = False
    ownership_change = False

    mutated_path = extract_path(mutated.get("url", "")) if mutated.get("url") else ""
    if mutated_path and is_public_resource_path(mutated_path):
        public_resource_context = True

    base_is_success = 200 <= base_status < 300
    mut_is_success = 200 <= mut_status < 300
    mut_is_auth_denial = mut_status in (401, 403)
    mut_is_missing = mut_status == 404

    # ---------- GENERIC empty/null response detection ----------
    mutated_body = mutated.get("body", "")
    mutated_length = mutated.get("length", 0)
    body_lower = mutated_body.lower()
    import re

    is_empty_likely = False
    if mutated_length < 50:
        # Strip whitespace and newlines for comparison
        stripped = re.sub(r'[\s\n\r]+', '', mutated_body).lower()
        # Common empty/status-only patterns
        empty_patterns = (
            '{}', '{"status":"success"}', '{"success":true}', '{"success":false}',
            '{"ok":true}', '{"ok":false}', '{"data":null}', '{"result":null}',
            '{"items":[]}', '{"data":[]}', '{"data":{}}', '[]'
        )
        if stripped in empty_patterns:
            is_empty_likely = True
        elif 'error' in body_lower and mutated_length < 100:
            is_empty_likely = True

    # Detect presence of real data objects (any JSON object with content)
    base_has_data_object = bool(re.search(r'"\w+":\s*\{', base.get("body", ""))) or "data." in base.get("body", "")
    mutated_has_data_object = bool(re.search(r'"\w+":\s*\{', mutated_body)) or "data." in mutated_body

    if is_empty_likely or (base_has_data_object and not mutated_has_data_object and mut_is_success):
        return {
            "score": 0,
            "verdict": "EMPTY_OR_NULL_RESPONSE",
            "reasons": ["Mutated response returned empty/null data – likely invalid object, not IDOR"],
            "field_diff": field_diff,
            "flags": {
                "auth_boundary_only": False,
                "successful_cross_object_behavior": False,
                "sensitive_disclosure_signal": False,
                "ownership_signal": False,
                "public_resource_context": public_resource_context,
                "is_empty_response": True,
                "user_id_changed": False,
                "ownership_change": False
            }
        }
    # ---------------------------------------------------------

    sensitive_changes = []
    for item in field_diff["changed"]:
        if sensitive_field_name(item["field"]):
            sensitive_changes.append(item["field"])

    sensitive_added = []
    for item in field_diff["added"]:
        if sensitive_field_name(item["field"]):
            sensitive_added.append(item["field"])

    sensitive_removed = []
    for item in field_diff["removed"]:
        if sensitive_field_name(item["field"]):
            sensitive_removed.append(item["field"])

    if sensitive_changes or sensitive_added or sensitive_removed:
        ownership_signal = True

    # ---------- GENERIC ownership change detection ----------
    # Common identity fields across APIs (case‑insensitive)
    identity_field_patterns = [
        r'userid', r'user_id', r'user\.id', r'owner', r'owner_id', r'owner\.id',
        r'account', r'account_id', r'account\.id', r'customer', r'customer_id',
        r'email', r'username', r'login', r'profile_id', r'user\.email',
        r'created_by', r'modified_by', r'author', r'creator', r'updater'
    ]

    for item in field_diff["changed"]:
        field_lower = item["field"].lower()
        for pattern in identity_field_patterns:
            if re.search(pattern, field_lower):
                user_id_changed = True
                ownership_change = True
                break
    for item in field_diff["added"]:
        field_lower = item["field"].lower()
        for pattern in identity_field_patterns:
            if re.search(pattern, field_lower):
                ownership_change = True
                break
    for item in field_diff["removed"]:
        field_lower = item["field"].lower()
        for pattern in identity_field_patterns:
            if re.search(pattern, field_lower):
                ownership_change = True
                break

    # If no ownership marker changed, it's not IDOR
    if not ownership_change and successful_cross_object_behavior:
        successful_cross_object_behavior = False
        reasons.append("no ownership marker changed – likely shared or public object")
    # -----------------------------------------------------------------

    if base_is_success and mut_is_success:
        score += 3
        reasons.append("both responses succeeded")

        if base.get("fingerprint") != mutated.get("fingerprint"):
            score += 3
            reasons.append("normalized response fingerprint differs under successful access")

        if abs(int(base.get("length", 0)) - int(mutated.get("length", 0))) > 20:
            score += 2
            reasons.append("response length differs under successful access")

        successful_cross_object_behavior = True

    if mut_is_success and sensitive_changes:
        score += 5
        reasons.append("sensitive fields changed under successful mutated access: " + ", ".join(sensitive_changes[:5]))
        sensitive_disclosure_signal = True

    if mut_is_success and sensitive_added:
        score += 4
        reasons.append("sensitive fields added under successful mutated access: " + ", ".join(sensitive_added[:5]))
        sensitive_disclosure_signal = True

    if mut_is_success and sensitive_removed:
        score += 3
        reasons.append("sensitive fields removed under successful mutated access: " + ", ".join(sensitive_removed[:5]))
        sensitive_disclosure_signal = True

    if base_is_success and mut_is_auth_denial:
        auth_boundary_only = True
        reasons.append(f"mutated request hit auth boundary ({mut_status})")
        score += 1

        if base.get("fingerprint") != mutated.get("fingerprint"):
            reasons.append("error response shape differs from successful baseline")

        if abs(int(base.get("length", 0)) - int(mutated.get("length", 0))) > 20:
            reasons.append("error response length differs from successful baseline")

    elif mut_is_missing:
        reasons.append("mutated request returned 404")

    elif mut_status >= 500:
        reasons.append(f"mutated request triggered server error ({mut_status})")
        score += 1

    elif base_status != mut_status:
        score += 1
        reasons.append(f"status changed from {base_status} to {mut_status}")

    if str(original_value).isdigit() and str(new_value).isdigit():
        score += 1
        reasons.append("id-like value manipulated")

    if sensitive_field_name(input_name):
        score += 1
        reasons.append("interesting input field manipulated")

    # ---------- object vanished detection (uses already computed flags) ----------
    if base_has_data_object and not mutated_has_data_object and mut_is_success and not is_empty_likely:
        verdict = "INVALID_OBJECT_REFERENCE"
        score = min(score, 3)
        reasons.append("Mutated response lost the data object – probably not a valid object")
        successful_cross_object_behavior = False
        ownership_signal = False
        sensitive_disclosure_signal = False
        is_empty_response = True
    # ----------------------------------------------

    elif auth_boundary_only and not successful_cross_object_behavior and not sensitive_disclosure_signal:
        verdict = "AUTH BOUNDARY DIFFERENCE"
        score = min(score, 4)

    elif successful_cross_object_behavior and public_resource_context and not ownership_change:
        verdict = "EXPECTED OBJECT VARIATION"
        score = min(score, 3)
        reasons.append("resource family appears public and no ownership-sensitive fields changed")

    elif successful_cross_object_behavior and sensitive_disclosure_signal and score >= 8 and ownership_change:
        verdict = "HIGH PROBABILITY IDOR"

    elif successful_cross_object_behavior and ownership_change and score >= 6:
        verdict = "POSSIBLE AUTH/OBJECT ISSUE"

    elif mut_is_auth_denial:
        verdict = "AUTH BOUNDARY DIFFERENCE"

    else:
        verdict = "LOW"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "field_diff": field_diff,
        "flags": {
            "auth_boundary_only": auth_boundary_only,
            "successful_cross_object_behavior": successful_cross_object_behavior,
            "sensitive_disclosure_signal": sensitive_disclosure_signal,
            "ownership_signal": ownership_signal,
            "public_resource_context": public_resource_context,
            "is_empty_response": is_empty_response,
            "user_id_changed": user_id_changed,
            "ownership_change": ownership_change
        }
    }

# ============================================
# AUTO MUTATION REPLAY
# ============================================

def should_auto_mutate(method: str, candidate_inputs: list[dict]) -> bool:
    if not AUTO_MUTATION_ENABLED:
        return False
    if method.upper() not in ("GET", "HEAD"):
        return False
    return any(
        p.get("classification") == "id-like" and p.get("mutation_presets")
        for p in candidate_inputs
    )


def apply_path_mutation(url: str, item: dict, new_value: str) -> str:
    parsed = urlparse(url)
    segments = parsed.path.strip("/").split("/")
    idx = item.get("path_segment_index")
    if idx is None or idx >= len(segments):
        return url

    segments[idx] = str(new_value)
    new_path = "/" + "/".join(segments)
    return urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))


def apply_query_mutation(url: str, item: dict, new_value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[item.get("name")] = [str(new_value)]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def auto_mutation_replay(url: str, method: str, headers: dict, body: str, current: dict, candidate_inputs: list[dict], program: str = "local-lab"):
    if not should_auto_mutate(method, candidate_inputs):
        return {
            "performed": False,
            "reason": "auto mutation not eligible for this request"
        }

    id_like_candidates = [
        p for p in meaningful_candidate_inputs(candidate_inputs)
        if p.get("classification") == "id-like" and p.get("mutation_presets")
    ]

    tested = 0
    results = []

    base_rich = {
        "status_code": current["status_code"],
        "length": current["length"],
        "fingerprint": current["fingerprint"],
        "fields": current.get("fields", response_json_fields(current.get("response_text", ""))),
        "normalized_fields": current.get("normalized_fields", normalized_response_fields(current.get("response_text", "")))
    }

    for item in id_like_candidates:
        original_value = item.get("sample_value", "")
        for mutation in item.get("mutation_presets", []):
            if tested >= AUTO_MUTATION_LIMIT:
                break

            try:
                if item.get("source") == "path":
                    mutated_url = apply_path_mutation(url, item, mutation)
                elif item.get("source") == "query":
                    mutated_url = apply_query_mutation(url, item, mutation)
                else:
                    continue

                mutated = perform_request(
                    method,
                    mutated_url,
                    headers,
                    body,
                    strip_auth=False,
                    timeout=AUTO_MUTATION_TIMEOUT,
                    program=program
                )
                mutated["url"] = mutated_url

                result = {
                    "input_name": item.get("name"),
                    "source": item.get("source"),
                    "mutation": str(mutation),
                    "mutated_url": mutated_url,
                    "status_code": mutated["status_code"],
                    "length": mutated["length"],
                    "fingerprint": mutated["fingerprint"],
                    "status_changed": mutated["status_code"] != base_rich["status_code"],
                    "length_changed": mutated["length"] != base_rich["length"],
                    "fingerprint_changed": mutated["fingerprint"] != base_rich["fingerprint"],
                    "analysis": exploit_confirmation(base_rich, mutated, item.get("name", ""), original_value, mutation)
                }

                results.append(result)
                tested += 1

            except Exception as e:
                results.append({
                    "input_name": item.get("name"),
                    "source": item.get("source"),
                    "mutation": str(mutation),
                    "error": str(e)
                })
                tested += 1

        if tested >= AUTO_MUTATION_LIMIT:
            break

    meaningful = [
        r for r in results
        if not r.get("error")
        and (
            r.get("status_changed")
            or r.get("length_changed")
            or r.get("fingerprint_changed")
            or (r.get("analysis", {}).get("score", 0) >= 5)
        )
    ]

    return {
        "performed": True,
        "tested_count": len(results),
        "meaningful_count": len(meaningful),
        "results": results
    }

# ============================================
# MULTI-AUTH REPLAY ENGINE
# ============================================

def file_multi_auth_profiles():
    path = MULTI_AUTH_PROFILES_FILE
    if not path:
        return []

    try:
        if not os.path.isabs(path):
            path = os.path.join(os.path.dirname(__file__), path)

        if not os.path.exists(path):
            return []

        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)

        if isinstance(loaded, list):
            return loaded

        return []
    except Exception as e:
        logger.warning("Failed loading multi-auth profiles file: %s", e)
        return []

def env_multi_auth_profiles():
    profiles = []

    if MULTI_AUTH_PROFILES_JSON.strip():
        loaded = safe_json_loads(MULTI_AUTH_PROFILES_JSON)
        if isinstance(loaded, list):
            profiles.extend(loaded)

    profiles.extend(file_multi_auth_profiles())
    return profiles

def normalize_multi_auth_profiles(payload_profiles):
    profiles = []

    base_profiles = []
    if isinstance(payload_profiles, list):
        base_profiles.extend(payload_profiles)
    base_profiles.extend(env_multi_auth_profiles())

    for p in base_profiles:
        if not isinstance(p, dict):
            continue

        label = str(p.get("label", "alt-auth")).strip() or "alt-auth"
        headers = p.get("headers", {}) or {}
        strip_auth = bool(p.get("strip_auth", False))

        if not isinstance(headers, dict):
            headers = {}

        profiles.append({
            "label": label,
            "headers": headers,
            "strip_auth": strip_auth
        })

    deduped = []
    seen = set()
    for p in profiles:
        key = (p["label"], json.dumps(p["headers"], sort_keys=True), p["strip_auth"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(p)

    return deduped


def merge_headers_for_profile(base_headers: dict, profile: dict):
    merged = dict(base_headers or {})
    merged.pop("X-API-Key", None)

    if profile.get("strip_auth"):
        merged.pop("Authorization", None)
        merged.pop("authorization", None)
        merged.pop("Cookie", None)
        merged.pop("cookie", None)

    for k, v in (profile.get("headers", {}) or {}).items():
        merged[k] = v

    return merged

def multi_auth_replay(url: str, method: str, headers: dict, body: str, current: dict,
                      candidate_inputs: list[dict], payload_profiles, program: str = "local-lab"):
    if not MULTI_AUTH_ENABLED:
        return {
            "performed": False,
            "reason": "multi-auth replay disabled"
        }

    if method.upper() not in ("GET", "HEAD"):
        return {
            "performed": False,
            "reason": "multi-auth replay limited to GET/HEAD"
        }

    profiles = normalize_multi_auth_profiles(payload_profiles)
    if not profiles:
        return {
            "performed": False,
            "reason": "no alternate auth profiles supplied"
        }

    id_like_candidates = [
        p for p in meaningful_candidate_inputs(candidate_inputs)
        if p.get("classification") == "id-like" and p.get("mutation_presets")
    ]

    if not id_like_candidates:
        return {
            "performed": False,
            "reason": "no id-like candidate inputs for multi-auth replay"
        }

    base_fields = current.get("fields", response_json_fields(current.get("response_text", "")))
    base_normalized_fields = current.get(
        "normalized_fields",
        normalized_response_fields(current.get("response_text", ""))
    )

    tested = 0
    results = []

    for item in id_like_candidates:
        original_value = item.get("sample_value", "")

        for mutation in item.get("mutation_presets", []):
            if tested >= MULTI_AUTH_LIMIT:
                break

            if item.get("source") == "path":
                mutated_url = apply_path_mutation(url, item, mutation)
            elif item.get("source") == "query":
                mutated_url = apply_query_mutation(url, item, mutation)
            else:
                continue

            for profile in profiles:
                if tested >= MULTI_AUTH_LIMIT:
                    break

                try:
                    replay_headers = merge_headers_for_profile(headers, profile)

                    mutated = perform_request(
                        method=method,
                        url=mutated_url,
                        headers=replay_headers,
                        body=body,
                        strip_auth=False,
                        timeout=MULTI_AUTH_TIMEOUT,
                        program=program
                    )

                    base_rich = {
                        "status_code": current["status_code"],
                        "length": current["length"],
                        "fingerprint": current["fingerprint"],
                        "fields": base_fields,
                        "normalized_fields": base_normalized_fields
                    }

                    analysis = exploit_confirmation(
                        base_rich,
                        mutated,
                        item.get("name", ""),
                        original_value,
                        mutation
                    )

                    results.append({
                        "profile_label": profile["label"],
                        "input_name": item.get("name"),
                        "source": item.get("source"),
                        "mutation": str(mutation),
                        "mutated_url": mutated_url,
                        "status_code": mutated["status_code"],
                        "length": mutated["length"],
                        "fingerprint": mutated["fingerprint"],
                        "status_changed": mutated["status_code"] != current["status_code"],
                        "length_changed": mutated["length"] != current["length"],
                        "fingerprint_changed": mutated["fingerprint"] != current["fingerprint"],
                        "normalized_fields": mutated.get("normalized_fields", {}),
                        "fields": mutated.get("fields", {}),
                        "analysis": analysis
                    })
                    tested += 1

                except Exception as e:
                    results.append({
                        "profile_label": profile["label"],
                        "input_name": item.get("name"),
                        "source": item.get("source"),
                        "mutation": str(mutation),
                        "mutated_url": mutated_url,
                        "error": str(e)
                    })
                    tested += 1

        if tested >= MULTI_AUTH_LIMIT:
            break

    meaningful = [
        r for r in results
        if not r.get("error")
        and (
            r.get("status_changed")
            or r.get("length_changed")
            or r.get("fingerprint_changed")
            or (r.get("analysis", {}).get("score", 0) >= 5)
        )
    ]

    high_conf = [
        r for r in results
        if not r.get("error")
        and r.get("analysis", {}).get("verdict") == "HIGH PROBABILITY IDOR"
        and 200 <= int(r.get("status_code", 0) or 0) < 300
    ]

    auth_boundary_only = [
        r for r in results
        if not r.get("error")
        and (r.get("analysis", {}).get("flags", {}) or {}).get("auth_boundary_only")
    ]

    # -------------------------------------------------
    # Group same mutated object across profiles
    # -------------------------------------------------
    grouped_by_object = {}
    for r in results:
        if r.get("error"):
            continue

        key = (
            r.get("input_name", ""),
            r.get("mutation", ""),
            r.get("mutated_url", "")
        )
        grouped_by_object.setdefault(key, []).append(r)

    corroborated_differences = []
    corroborated_auth_boundaries = []
    corroborated_shared = []

    for key, group in grouped_by_object.items():
        if len(group) < 2:
            continue

        # Compare first pairwise profiles for same mutated object
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                a = group[i]
                b = group[j]

                cmp_result = corroboration_verdict(a, b)
                entry = {
                    "input_name": a.get("input_name"),
                    "mutation": a.get("mutation"),
                    "mutated_url": a.get("mutated_url"),
                    "profile_a": a.get("profile_label"),
                    "profile_b": b.get("profile_label"),
                    "comparison": cmp_result
                }

                verdict = cmp_result.get("verdict")

                if verdict in {"CROSS_USER_OBJECT_VARIANCE", "POSSIBLE_CROSS_USER_ACCESS"}:
                    corroborated_differences.append(entry)
                elif verdict == "AUTH_BOUNDARY_ONLY":
                    corroborated_auth_boundaries.append(entry)
                elif verdict == "SHARED_OR_PUBLIC_OBJECT":
                    corroborated_shared.append(entry)

    return {
        "performed": True,
        "profiles_used": [p["label"] for p in profiles],
        "tested_count": len(results),
        "meaningful_count": len(meaningful),
        "high_confidence_count": len(high_conf),
        "auth_boundary_count": len(auth_boundary_only),
        "results": results,
        "corroborated_difference_count": len(corroborated_differences),
        "corroborated_auth_boundary_count": len(corroborated_auth_boundaries),
        "corroborated_shared_count": len(corroborated_shared),
        "corroborated_differences": corroborated_differences,
        "corroborated_auth_boundaries": corroborated_auth_boundaries,
        "corroborated_shared": corroborated_shared
    }

# ============================================
# TRUE CROSS-USER CORROBORATION
# ============================================

def profile_label_from_result(result: dict) -> str:
    return str(result.get("profile_label", "unknown")).strip() or "unknown"


def is_success_status(status_code: int) -> bool:
    try:
        code = int(status_code or 0)
        return 200 <= code < 300
    except Exception:
        return False


def extract_identity_markers_from_fields(fields: dict):
    """
    Pull likely ownership markers out of normalized response fields.
    This is heuristic but much safer than relying on status alone.
    """
    markers = {}

    if not isinstance(fields, dict):
        return markers

    interesting_terms = [
        "user", "user.id", "user.email", "user.username",
        "email", "username", "account", "account.id", "account.email",
        "customer", "customer.id", "customer.email",
        "owner", "owner.id", "owner.email", "owner.username",
        "profile.id", "profile.email", "profile.username",
        "basket.id", "order.id", "wallet.id", "address.id"
    ]

    for k, v in fields.items():
        lk = str(k).lower()
        for term in interesting_terms:
            if term in lk:
                markers[k] = str(v)
                break

    return markers


def compare_identity_markers(base_markers: dict, other_markers: dict):
    changed = []
    same = []

    shared_keys = sorted(set(base_markers.keys()) & set(other_markers.keys()))
    for k in shared_keys:
        if base_markers[k] == other_markers[k]:
            same.append({
                "field": k,
                "value": base_markers[k]
            })
        else:
            changed.append({
                "field": k,
                "base": base_markers[k],
                "other": other_markers[k]
            })

    return {
        "changed": changed,
        "same": same
    }


def corroboration_verdict(base_result: dict, alt_result: dict):
    """
    Stronger than generic diffing:
    decide whether alternate auth got the same object,
    a different object, or simply hit an auth boundary.
    """
    base_status = int(base_result.get("status_code", 0) or 0)
    alt_status = int(alt_result.get("status_code", 0) or 0)

    base_success = is_success_status(base_status)
    alt_success = is_success_status(alt_status)

    base_fields = base_result.get("normalized_fields", {}) or {}
    alt_fields = alt_result.get("normalized_fields", {}) or {}

    base_markers = extract_identity_markers_from_fields(base_fields)
    alt_markers = extract_identity_markers_from_fields(alt_fields)
    marker_cmp = compare_identity_markers(base_markers, alt_markers)

    field_diff = diff_response_fields(base_fields, alt_fields)

    verdict = "NO_STRONG_FINDING"
    confidence = "low"
    reasons = []

    # Case 1: auth boundary only
    if base_success and not alt_success and alt_status in (401, 403):
        verdict = "AUTH_BOUNDARY_ONLY"
        confidence = "medium"
        reasons.append("base profile succeeded while alternate profile was denied")

    # Case 2: both succeed and identity markers change
    elif base_success and alt_success and marker_cmp["changed"]:
        verdict = "CROSS_USER_OBJECT_VARIANCE"
        confidence = "high"
        reasons.append("both profiles succeeded and ownership/identity markers changed")

    # Case 3: both succeed and fingerprints differ materially
    elif base_success and alt_success and base_result.get("fingerprint") != alt_result.get("fingerprint"):
        verdict = "POSSIBLE_CROSS_USER_ACCESS"
        confidence = "medium"
        reasons.append("both profiles succeeded with materially different response shape")

    # Case 4: both succeed and same markers
    elif base_success and alt_success and marker_cmp["same"]:
        verdict = "SHARED_OR_PUBLIC_OBJECT"
        confidence = "medium"
        reasons.append("both profiles succeeded and key markers matched")

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasons": reasons,
        "base_status": base_status,
        "alt_status": alt_status,
        "base_success": base_success,
        "alt_success": alt_success,
        "base_identity_markers": base_markers,
        "alt_identity_markers": alt_markers,
        "identity_marker_comparison": marker_cmp,
        "field_diff": field_diff
    }


def true_cross_user_corroboration(url: str, method: str, headers: dict, body: str,
                                  current: dict, candidate_inputs: list[dict],
                                  payload_profiles, program: str = "local-lab"):
    """
    Replays the SAME mutated object under multiple supplied auth profiles
    and checks whether the object appears user-bound, shared, or improperly exposed.
    """
    if not MULTI_AUTH_ENABLED:
        return {
            "performed": False,
            "reason": "multi-auth disabled"
        }

    if method.upper() not in ("GET", "HEAD"):
        return {
            "performed": False,
            "reason": "cross-user corroboration limited to GET/HEAD"
        }

    profiles = normalize_multi_auth_profiles(payload_profiles)
    if len(profiles) < 2:
        return {
            "performed": False,
            "reason": "need at least two auth profiles for corroboration"
        }

    id_like_candidates = [
        p for p in candidate_inputs
        if p.get("classification") == "id-like" and p.get("mutation_presets")
    ]
    if not id_like_candidates:
        return {
            "performed": False,
            "reason": "no id-like candidates for corroboration"
        }

    tested = []
    comparisons = []

    # Keep it bounded: first two profiles, first two id candidates, first two mutations
    selected_profiles = profiles[:2]
    selected_candidates = id_like_candidates[:2]

    for item in selected_candidates:
        for mutation in item.get("mutation_presets", [])[:2]:
            if item.get("source") == "path":
                mutated_url = apply_path_mutation(url, item, mutation)
            elif item.get("source") == "query":
                mutated_url = apply_query_mutation(url, item, mutation)
            else:
                continue

            profile_results = []

            for profile in selected_profiles:
                try:
                    replay_headers = merge_headers_for_profile(headers, profile)
                    replay = perform_request(
                        method=method,
                        url=mutated_url,
                        headers=replay_headers,
                        body=body,
                        strip_auth=False,
                        timeout=MULTI_AUTH_TIMEOUT,
                        program=program
                    )

                    profile_results.append({
                        "profile_label": profile["label"],
                        "input_name": item.get("name"),
                        "mutation": str(mutation),
                        "mutated_url": mutated_url,
                        "status_code": replay["status_code"],
                        "length": replay["length"],
                        "fingerprint": replay["fingerprint"],
                        "normalized_fields": replay.get("normalized_fields", {}),
                        "fields": replay.get("fields", {})
                    })
                except Exception as e:
                    profile_results.append({
                        "profile_label": profile["label"],
                        "input_name": item.get("name"),
                        "mutation": str(mutation),
                        "mutated_url": mutated_url,
                        "error": str(e)
                    })

            tested.append({
                "input_name": item.get("name"),
                "mutation": str(mutation),
                "mutated_url": mutated_url,
                "profiles": profile_results
            })

            successful = [x for x in profile_results if not x.get("error")]
            if len(successful) >= 2:
                base = successful[0]
                other = successful[1]
                cmp_result = corroboration_verdict(base, other)

                comparisons.append({
                    "input_name": item.get("name"),
                    "mutation": str(mutation),
                    "mutated_url": mutated_url,
                    "base_profile": base.get("profile_label"),
                    "other_profile": other.get("profile_label"),
                    "comparison": cmp_result
                })

    strong_findings = [
        c for c in comparisons
        if c.get("comparison", {}).get("verdict") in {
            "CROSS_USER_OBJECT_VARIANCE",
            "POSSIBLE_CROSS_USER_ACCESS"
        }
    ]

    auth_boundary_only = [
        c for c in comparisons
        if c.get("comparison", {}).get("verdict") == "AUTH_BOUNDARY_ONLY"
    ]

    shared_or_public = [
        c for c in comparisons
        if c.get("comparison", {}).get("verdict") == "SHARED_OR_PUBLIC_OBJECT"
    ]

    return {
        "performed": True,
        "profiles_used": [p["label"] for p in selected_profiles],
        "tested": tested,
        "comparisons": comparisons,
        "meaningful_count": len(comparisons),
        "strong_finding_count": len(strong_findings),
        "auth_boundary_count": len(auth_boundary_only),
        "shared_or_public_count": len(shared_or_public),
        "strong_findings": strong_findings
    }

# ============================================
# AUTO EXPLOIT REPLAY ENGINE
# ============================================

def select_exploit_candidates(mutation_replay: dict, multi_auth_result: dict, graph: dict = None, attack_chain: dict = None):
    candidates = []

    graph_families = set(graph_object_families(graph)) if graph else set()
    edge_memory = graph.get("persistent_edge_memory", []) if graph else []
    auth_memory = graph.get("persistent_auth_memory", []) if graph else []

    chain_stage = ""
    chain_neighbors = []
    if attack_chain:
        chain_stage = attack_chain.get("seed", {}).get("stage", "")
        chain_neighbors = [n.get("target", "") for n in attack_chain.get("neighbors", [])]

    def score_candidate(candidate_type: str, r: dict):
        score = 0

        analysis = r.get("analysis", {})
        verdict = analysis.get("verdict", "")
        flags = analysis.get("flags", {}) or {}

        if verdict == "HIGH PROBABILITY IDOR":
            score += 50
        elif verdict == "POSSIBLE AUTH/OBJECT ISSUE":
            score += 30
        else:
            score += 0

        if r.get("status_changed"):
            score += 10
        if r.get("fingerprint_changed"):
            score += 15
        if r.get("length_changed"):
            score += 8

        if flags.get("successful_cross_object_behavior"):
            score += 20

        if flags.get("sensitive_disclosure_signal"):
            score += 20

        if flags.get("auth_boundary_only"):
            score -= 30

        mutated_url = r.get("mutated_url", "")
        mutated_path = extract_path(mutated_url) if mutated_url else ""

        for fam in graph_families:
            if fam and fam in mutated_path.lower():
                score += 10

        for edge in edge_memory:
            token = edge.get("to_token", "")
            if token and token in mutated_url:
                score += 10

        if len(auth_memory) > 1:
            score += 5

        if candidate_type == "multi-auth":
            score += 10

        if chain_stage in {"object-access", "identity-resource", "action"}:
            score += 8

        for n in chain_neighbors:
            if n and n in mutated_url:
                score += 8

        if "checkout" in mutated_path.lower() or "payment" in mutated_path.lower():
            score += 10

        return score

    def eligible_result(r: dict):
        if r.get("error"):
            return False

        analysis = r.get("analysis", {})
        verdict = analysis.get("verdict", "")
        flags = analysis.get("flags", {}) or {}

        if flags.get("auth_boundary_only"):
            return False

        if flags.get("public_resource_context") and not flags.get("ownership_signal"):
            return False

        if verdict == "HIGH PROBABILITY IDOR":
            return True

        if verdict == "POSSIBLE AUTH/OBJECT ISSUE" and flags.get("successful_cross_object_behavior"):
            return True

        mut_status = int(r.get("status_code", 0) or 0)
        if (
            200 <= mut_status < 300
            and flags.get("ownership_signal")
            and (
                r.get("fingerprint_changed")
                or r.get("length_changed")
                or analysis.get("score", 0) >= 5
            )
        ):
            return True

        return False

    for r in mutation_replay.get("results", []):
        if eligible_result(r):
            candidates.append({
                "type": "mutation",
                "data": r,
                "priority_score": score_candidate("mutation", r)
            })

    for r in multi_auth_result.get("results", []):
        if eligible_result(r):
            candidates.append({
                "type": "multi-auth",
                "data": r,
                "priority_score": score_candidate("multi-auth", r)
            })

    # Deduplicate candidates
    seen = set()
    deduped = []
    for c in candidates:
        data = c.get("data", {}) or {}
        key = (
            c.get("type", ""),
            data.get("mutated_url", ""),
            data.get("profile_label", ""),
            data.get("mutation", "")
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)

    deduped.sort(key=lambda x: x["priority_score"], reverse=True)
    return deduped[:AUTO_EXPLOIT_REPLAY_LIMIT]

def replay_candidate(method: str, headers: dict, body: str, candidate: dict, payload_profiles=None, program: str = "local-lab"):
    try:
        url = candidate["data"].get("mutated_url")
        replay_headers = dict(headers or {})

        if candidate["type"] == "multi-auth":
            profile_label = candidate["data"].get("profile_label", "")
            profiles = normalize_multi_auth_profiles(payload_profiles or [])
            matched = None
            for p in profiles:
                if p["label"] == profile_label:
                    matched = p
                    break
            if matched is not None:
                replay_headers = merge_headers_for_profile(headers, matched)

        result = perform_request(
            method=method,
            url=url,
            headers=replay_headers,
            body=body,
            strip_auth=False,
            timeout=AUTO_EXPLOIT_REPLAY_TIMEOUT,
            program=program
        )

        return result

    except Exception as e:
        return {"error": str(e)}



def auto_exploit_replay(
    url: str,
    method: str,
    headers: dict,
    body: str,
    current: dict,
    mutation_replay: dict,
    multi_auth_result: dict,
    graph: dict = None,
    payload_profiles=None,
    attack_chain: dict = None,
    program: str = "local-lab"
):
    if not AUTO_EXPLOIT_REPLAY_ENABLED:
        return {
            "performed": False,
            "reason": "auto exploit replay disabled"
        }

    candidates = select_exploit_candidates(
        mutation_replay,
        multi_auth_result,
        graph,
        attack_chain
    )
    if not candidates:
        return {
            "performed": False,
            "reason": "no viable exploit candidates"
        }

    results = []

    base = {
        "status_code": current["status_code"],
        "length": current["length"],
        "fingerprint": current["fingerprint"],
        "fields": current.get("fields", response_json_fields(current.get("response_text", ""))),
        "normalized_fields": current.get("normalized_fields", normalized_response_fields(current.get("response_text", "")))
    }

    def attempt_is_strong_confirmation(attempt_analysis: dict, corroboration_flags: dict = None, user_id_changed: bool = False) -> bool:
        if not attempt_analysis:
            return False

        verdict = attempt_analysis.get("verdict", "")
        score = int(attempt_analysis.get("score", 0) or 0)
        flags = attempt_analysis.get("flags", {}) or {}
        field_diff = attempt_analysis.get("field_diff", {}) or {}

        if flags.get("is_empty_response", False):
            return False

        # If corroboration says shared/public, cannot confirm
        if corroboration_flags:
            if corroboration_flags.get("verdict") in ("SHARED_OR_PUBLIC_OBJECT", "NO_STRONG_FINDING"):
                return False

        # Must have a UserId or ownership change
        if not user_id_changed:
            return False

        changed = field_diff.get("changed", []) or []
        added = field_diff.get("added", []) or []
        removed = field_diff.get("removed", []) or []

        sensitive_changed = any(sensitive_field_name(x.get("field", "")) for x in changed)
        sensitive_added = any(sensitive_field_name(x.get("field", "")) for x in added)
        sensitive_removed = any(sensitive_field_name(x.get("field", "")) for x in removed)

        if flags.get("auth_boundary_only"):
            return False

        if verdict == "HIGH PROBABILITY IDOR":
            return True

        if flags.get("successful_cross_object_behavior") and flags.get("sensitive_disclosure_signal"):
            return True

        if flags.get("successful_cross_object_behavior") and (sensitive_changed or sensitive_added or sensitive_removed):
            return True

        if score >= 8 and flags.get("successful_cross_object_behavior"):
            return True

        return False

    for c in candidates:
        stable_hits = 0
        strong_hits = 0
        attempts = []

        # Look up corroboration flags once per candidate
        target_url = c["data"].get("mutated_url", "")
        corroboration_flags = None
        for shared in multi_auth_result.get("corroborated_shared", []):
            if shared.get("mutated_url") == target_url:
                corroboration_flags = shared.get("comparison", {})
                break
        if not corroboration_flags:
            for diff in multi_auth_result.get("corroborated_differences", []):
                if diff.get("mutated_url") == target_url:
                    corroboration_flags = diff.get("comparison", {})
                    break

        for _ in range(AUTO_EXPLOIT_REPLAY_ROUNDS):
            replay = replay_candidate(method, headers, body, c, payload_profiles, program)

            if replay.get("error"):
                attempts.append({"error": replay["error"]})
                continue

            analysis = exploit_confirmation(
                base,
                replay,
                c["data"].get("input_name", ""),
                "",
                c["data"].get("mutation", "")
            )

            user_id_changed = analysis.get("flags", {}).get("user_id_changed", False)
            strong_confirmation = attempt_is_strong_confirmation(analysis, corroboration_flags, user_id_changed)

            attempts.append({
                "status": replay["status_code"],
                "length": replay["length"],
                "fingerprint": replay["fingerprint"],
                "analysis": analysis,
                "strong_confirmation": strong_confirmation
            })

            if analysis["score"] >= 5:
                stable_hits += 1

            if strong_confirmation:
                strong_hits += 1

        stable = stable_hits >= AUTO_EXPLOIT_REPLAY_ROUNDS
        confirmed = strong_hits >= AUTO_EXPLOIT_REPLAY_ROUNDS

        results.append({
            "type": c["type"],
            "target": c["data"].get("mutated_url"),
            "stable": stable,
            "confirmed": confirmed,
            "stable_hits": stable_hits,
            "strong_hits": strong_hits,
            "attempts": attempts
        })

    confirmed_results = [r for r in results if r.get("confirmed")]
    stable_only_results = [r for r in results if r.get("stable") and not r.get("confirmed")]

    return {
        "performed": True,
        "tested": len(results),
        "confirmed": len(confirmed_results),
        "stable_only": len(stable_only_results),
        "results": results
    }
# ========== PHASE 4: DECISION ENGINE ==========
def run_decision_engine(trace_id: str, trace_bundle: dict, intel: dict, score: int, next_actions: list) -> dict:
    """
    Execute the highest‑priority next actions automatically.
    Returns a summary of what was done.
    """
    results = {"executed_actions": [], "skipped": []}
    program = trace_bundle.get("program", "local-lab")

    for action in next_actions:
        if action["priority"] != "high":
            results["skipped"].append({"action": action["action"], "reason": "priority not high"})
            continue

        if action["action"] == "run_id_mutation_tests":
            # Re‑run auto_mutation_replay if not already done
            if not trace_bundle.get("mutation_replay", {}).get("performed"):
                mutation = auto_mutation_replay(
                    url=trace_bundle["url"],
                    method=trace_bundle["method"],
                    headers=trace_bundle["request_headers"],
                    body=trace_bundle["request_body"],
                    current=trace_bundle["current"],
                    candidate_inputs=trace_bundle["candidate_inputs"],
                    program=program
                )
                results["executed_actions"].append({"action": "run_id_mutation_tests", "result": mutation.get("meaningful_count", 0)})

        elif action["action"] == "run_multi_auth_replay":
            if not trace_bundle.get("multi_auth_result", {}).get("performed"):
                multi = multi_auth_replay(
                    url=trace_bundle["url"],
                    method=trace_bundle["method"],
                    headers=trace_bundle["request_headers"],
                    body=trace_bundle["request_body"],
                    current=trace_bundle["current"],
                    candidate_inputs=trace_bundle["candidate_inputs"],
                    payload_profiles=trace_bundle.get("payload_multi_auth_profiles", []),
                    program=program
                )
                results["executed_actions"].append({"action": "run_multi_auth_replay", "result": multi.get("meaningful_count", 0)})

        elif action["action"] == "pivot_same_family_endpoints":
            # Trigger a lightweight pivot on the same family
            graph = endpoint_intelligence_graph(
                path=trace_bundle["path"],
                method=trace_bundle["method"],
                candidate_inputs=trace_bundle["candidate_inputs"],
                history=[],
                signals=[]
            )
            family_pivots = graph_related_endpoint_patterns(graph, max_patterns=3)
            results["executed_actions"].append({"action": "pivot_same_family_endpoints", "result": family_pivots})

    return results

# ========== PHASE 5: HYPOTHESIS RANKING & SMART PAYLOADS ==========
def rank_hypotheses(trace_bundle: dict, intel: dict, mutation_result: dict, multi_auth_result: dict) -> list:
    hypotheses = []
    if intel.get("has_object_id_surface") and mutation_result.get("meaningful_count", 0) > 0:
        hypotheses.append({
            "type": "idor",
            "confidence": "high",
            "evidence": f"ID mutations produced {mutation_result['meaningful_count']} meaningful changes"
        })
    if mutation_result.get("performed") and any(r.get("analysis", {}).get("verdict") == "AUTH BOUNDARY DIFFERENCE" for r in mutation_result.get("results", [])):
        hypotheses.append({
            "type": "auth_bypass",
            "confidence": "medium",
            "evidence": "Auth boundary difference detected"
        })
    if intel.get("mentions_admin") and multi_auth_result.get("high_confidence_count", 0) > 0:
        hypotheses.append({
            "type": "privilege_escalation",
            "confidence": "high",
            "evidence": "Admin keywords appear and multi‑auth shows access"
        })
    return hypotheses

def generate_smart_payloads(intel: dict, hypothesis: dict) -> list:
    payloads = []
    if hypothesis["type"] == "idor":
        payloads.extend(["0", "1", "-1", "999999", "null", "true", "false"])
    elif hypothesis["type"] == "auth_bypass":
        payloads.extend(["", "null", "admin", "' OR '1'='1", "..;/admin"])
    return payloads

# ============================================
# DIFF ENGINE
# ============================================

def compute_diff(current: dict, replay: dict, history: list[dict]):
    diffs = []

    if replay and replay.get("performed") and "error" not in replay:
        if current["status_code"] != replay.get("status_code"):
            diffs.append({
                "type": "auth-status-diff",
                "severity": "high",
                "detail": f"current status {current['status_code']} vs replay status {replay.get('status_code')}"
            })

        if current["length"] != replay.get("length"):
            diffs.append({
                "type": "auth-length-diff",
                "severity": "medium",
                "detail": f"current length {current['length']} vs replay length {replay.get('length')}"
            })

        if current["fingerprint"] != replay.get("fingerprint"):
            diffs.append({
                "type": "auth-fingerprint-diff",
                "severity": "high",
                "detail": "authenticated and unauthenticated bodies differ"
            })

    if history:
        latest = history[-1]

        if latest["status_code"] != current["status_code"]:
            diffs.append({
                "type": "historical-status-diff",
                "severity": "medium",
                "detail": f"current status {current['status_code']} vs prior status {latest['status_code']}"
            })

        if latest["response_length"] != current["length"]:
            diffs.append({
                "type": "historical-length-diff",
                "severity": "low",
                "detail": f"current length {current['length']} vs prior length {latest['response_length']}"
            })

        if latest["fingerprint"] != current["fingerprint"]:
            diffs.append({
                "type": "historical-fingerprint-diff",
                "severity": "medium",
                "detail": "current response shape differs from a prior observation"
            })

    return diffs


# ============================================
# DETECTION SIGNALS
# ============================================

def detection_signals(path, params, diff, mutation, multi_auth, exploit, corroboration=None):
    signals = []
    corroboration = corroboration or {}
    diff_types = {d["type"] for d in diff}

    # -----------------------------
    # AUTH DIFFERENCE SIGNALS
    # -----------------------------
    if "auth-fingerprint-diff" in diff_types:
        signals.append({
            "type": "auth-content-diff",
            "severity": "high",
            "detail": "authenticated and unauthenticated responses differ in shape"
        })

    if "auth-length-diff" in diff_types:
        signals.append({
            "type": "auth-length-diff",
            "severity": "medium",
            "detail": "authenticated and unauthenticated responses differ in size"
        })

    # -----------------------------
    # OBJECT SURFACE
    # -----------------------------
    if any(p["classification"] == "id-like" for p in params):
        signals.append({
            "type": "object-reference-surface",
            "severity": "high",
            "detail": "identifier-like object surface detected"
        })

    if any(p.get("source") == "path" and p["classification"] == "id-like" for p in params):
        signals.append({
            "type": "path-object-surface",
            "severity": "high",
            "detail": "path-based object identifier detected"
        })

    # -----------------------------
    # MUTATION ANALYSIS
    # -----------------------------
    mutation_results = mutation.get("results", [])

    if mutation.get("meaningful_count", 0) > 0:
        signals.append({
            "type": "mutation-behavior-diff",
            "severity": "high",
            "detail": f"{mutation.get('meaningful_count', 0)} mutation replay(s) changed behavior"
        })

    mutation_high_idor = []
    mutation_auth_boundary = []

    for r in mutation_results:
        if r.get("error"):
            continue

        analysis = r.get("analysis", {})
        verdict = analysis.get("verdict", "")
        flags = analysis.get("flags", {}) or {}

        mut_status = int(r.get("status_code", 0) or 0)
        mut_success = 200 <= mut_status < 300

        if verdict == "HIGH PROBABILITY IDOR" and mut_success:
            mutation_high_idor.append(r)

        if flags.get("auth_boundary_only"):
            mutation_auth_boundary.append(r)

    mutation_high_idor_filtered = []
    for r in mutation_high_idor:
        flags = r.get("analysis", {}).get("flags", {}) or {}
        if not flags.get("is_empty_response", False):
            mutation_high_idor_filtered.append(r)

    if mutation_high_idor_filtered:
        signals.append({
            "type": "high-probability-idor",
            "severity": "high",
            "detail": f"{len(mutation_high_idor_filtered)} mutation replay(s) showed successful cross-object access"
        })

    if mutation_auth_boundary:
        signals.append({
            "type": "mutation-auth-boundary",
            "severity": "medium",
            "detail": f"{len(mutation_auth_boundary)} mutation replay(s) hit authentication boundary"
        })

    # Detect empty/null responses
    for r in mutation_results:
        if r.get("error"):
            continue
        flags = r.get("analysis", {}).get("flags", {}) or {}
        if flags.get("is_empty_response"):
            signals.append({
                "type": "empty-or-null-response",
                "severity": "low",
                "detail": f"Mutation {r.get('mutation', '')} returned empty/null response – likely invalid object"
            })
            break

    # -----------------------------
    # MULTI-AUTH ANALYSIS
    # -----------------------------
    multi_auth_results = multi_auth.get("results", [])

    if multi_auth.get("meaningful_count", 0) > 0:
        signals.append({
            "type": "multi-auth-diff",
            "severity": "high",
            "detail": f"{multi_auth.get('meaningful_count', 0)} multi-auth replay(s) changed behavior across profiles"
        })

    multi_auth_high_idor = []
    multi_auth_boundary = []

    for r in multi_auth_results:
        if r.get("error"):
            continue

        analysis = r.get("analysis", {})
        verdict = analysis.get("verdict", "")
        flags = analysis.get("flags", {}) or {}

        mut_status = int(r.get("status_code", 0) or 0)
        mut_success = 200 <= mut_status < 300

        if verdict == "HIGH PROBABILITY IDOR" and mut_success:
            multi_auth_high_idor.append(r)

        if flags.get("auth_boundary_only"):
            multi_auth_boundary.append(r)

    multi_auth_high_idor_filtered = []
    for r in multi_auth_high_idor:
        flags = r.get("analysis", {}).get("flags", {}) or {}
        if not flags.get("is_empty_response", False):
            multi_auth_high_idor_filtered.append(r)

    if multi_auth_high_idor_filtered:
        signals.append({
            "type": "multi-auth-high-confidence-idor",
            "severity": "high",
            "detail": f"{len(multi_auth_high_idor_filtered)} multi-auth replay(s) showed successful cross-account access"
        })

    if multi_auth_boundary:
        signals.append({
            "type": "multi-auth-auth-boundary",
            "severity": "medium",
            "detail": f"{len(multi_auth_boundary)} multi-auth replay(s) produced auth boundary differences"
        })

    if multi_auth.get("corroborated_difference_count", 0) > 0:
        signals.append({
            "type": "multi-auth-same-object-difference",
            "severity": "critical",
            "detail": (
                f"{multi_auth.get('corroborated_difference_count', 0)} same-object "
                f"cross-profile comparison(s) showed materially different behavior"
            )
        })

    if multi_auth.get("corroborated_auth_boundary_count", 0) > 0:
        signals.append({
            "type": "multi-auth-same-object-auth-boundary",
            "severity": "medium",
            "detail": (
                f"{multi_auth.get('corroborated_auth_boundary_count', 0)} same-object "
                f"cross-profile comparison(s) showed denial/auth-boundary behavior"
            )
        })

    if multi_auth.get("corroborated_shared_count", 0) > 0:
        signals.append({
            "type": "multi-auth-same-object-shared",
            "severity": "low",
            "detail": (
                f"{multi_auth.get('corroborated_shared_count', 0)} same-object "
                f"cross-profile comparison(s) looked shared or public"
            )
        })

    # -----------------------------
    # EXPLOIT CONFIRMATION
    # -----------------------------
    if exploit.get("confirmed", 0) > 0:
        signals.append({
            "type": "confirmed-exploit",
            "severity": "critical",
            "detail": f"{exploit.get('confirmed', 0)} exploit replay(s) confirmed strong repeated exploit behavior"
        })

    if exploit.get("stable_only", 0) > 0:
        signals.append({
            "type": "stable-exploit-behavior",
            "severity": "medium",
            "detail": f"{exploit.get('stable_only', 0)} exploit replay candidate(s) were stable but not strong enough for full confirmation"
        })

    # -----------------------------
    # CROSS-USER CORROBORATION
    # -----------------------------
    if corroboration.get("performed") and corroboration.get("strong_finding_count", 0) > 0:
        signals.append({
            "type": "cross-user-corroborated-object-access",
            "severity": "critical",
            "detail": f"{corroboration.get('strong_finding_count', 0)} cross-user corroborated finding(s) suggest true object-level access difference"
        })

    if corroboration.get("performed") and (
        corroboration.get("strong_finding_count", 0) > 0
        or corroboration.get("auth_boundary_count", 0) > 0
        or corroboration.get("shared_or_public_count", 0) > 0
    ):
        total_meaningful = (
            corroboration.get("strong_finding_count", 0)
            + corroboration.get("auth_boundary_count", 0)
            + corroboration.get("shared_or_public_count", 0)
        )
        signals.append({
            "type": "cross-user-corroboration-diff",
            "severity": "high",
            "detail": (
                f"{total_meaningful} corroboration comparison(s) completed; "
                f"{corroboration.get('strong_finding_count', 0)} strong, "
                f"{corroboration.get('auth_boundary_count', 0)} auth-boundary, "
                f"{corroboration.get('shared_or_public_count', 0)} shared/public"
            )
        })

    # -----------------------------
    # BUSINESS CONTEXT
    # -----------------------------
    if is_business_path(path):
        signals.append({
            "type": "business-endpoint",
            "severity": "medium",
            "detail": "endpoint appears business-relevant"
        })

    return signals


# ============================================
# RISK SCORE
# ============================================

def compute_risk(signals):
    score = 0
    reasons = []

    signal_types = {s["type"] for s in signals}

    for s in signals:
        sev = s["severity"]
        if sev == "critical":
            score += 30
        elif sev == "high":
            score += 18
        elif sev == "medium":
            score += 8
        else:
            score += 4

        reasons.append(s["type"])

    # Graph-based bump
    if "graph-related-endpoints" in signal_types:
        score += 6
    if "graph-object-family" in signal_types:
        score += 6
    if "graph-flow-hints" in signal_types:
        score += 4

    # Persistent memory boost
    if "graph-node-recurrence" in signal_types:
        score += 6
    if "graph-recurring-object-links" in signal_types:
        score += 6
    if "graph-auth-diversity" in signal_types:
        score += 6

    # Attack-chain boost
    if "attack-chain-stage" in signal_types:
        score += 6
    if "attack-chain-neighbors" in signal_types:
        score += 6
    if "attack-chain-hypotheses" in signal_types:
        score += 6

    # Strong positive case: confirmed exploit matters a lot
    if "confirmed-exploit" in signal_types:
        score += 20

    # Stable but weaker replay evidence
    if "stable-exploit-behavior" in signal_types:
        score += 6

    # High-confidence IDOR without confirmed replay still matters
    if "high-probability-idor" in signal_types:
        score += 12

    if "multi-auth-high-confidence-idor" in signal_types:
        score += 12

    # Multi-auth same-object corroboration
    if "multi-auth-same-object-difference" in signal_types:
        score += 18

    if "multi-auth-same-object-auth-boundary" in signal_types:
        score += 4

    if "multi-auth-same-object-shared" in signal_types:
        score -= 20   # much stronger penalty

    # If all multi-auth corroboration says shared/public, cap risk
    if "multi-auth-same-object-shared" in signal_types and "multi-auth-same-object-difference" not in signal_types:
        score = min(score, 50)

    # Cross-user corroboration boosts
    if "cross-user-corroboration-diff" in signal_types:
        score += 10

    if "cross-user-corroborated-object-access" in signal_types:
        score += 18

    # Strongest combo: repeated exploit + same-object cross-user corroboration
    if (
        "confirmed-exploit" in signal_types
        and "cross-user-corroborated-object-access" in signal_types
    ):
        score += 12

    # Denial-only auth boundaries should not explode the score
    auth_boundary_only = (
        "auth-content-diff" in signal_types
        and "auth-length-diff" in signal_types
        and "confirmed-exploit" not in signal_types
        and "high-probability-idor" not in signal_types
        and "multi-auth-high-confidence-idor" not in signal_types
        and "cross-user-corroborated-object-access" not in signal_types
        and "multi-auth-same-object-difference" not in signal_types
    )

    if auth_boundary_only:
        score = min(score, 55)

    # If the main finding is just an empty response, cap low
    if any(s.get("type") == "empty-or-null-response" for s in signals):
        score = min(score, 20)

    return max(0, min(score, 100)), reasons


# ============================================
# OUTPUT PRIORITIZATION / SORTING
# ============================================
def sort_detection_signals(signals: list[dict]):
    if not isinstance(signals, list):
        return signals

    return sorted(
        signals,
        key=lambda s: (
            severity_rank(s.get("severity", "low")),
            len(str(s.get("detail", "")))
        ),
        reverse=True
    )


def sort_exploit_suggestions(suggestions: list[dict]):
    if not isinstance(suggestions, list):
        return suggestions

    return sorted(
        suggestions,
        key=lambda s: (
            priority_rank(s.get("priority", "low")),
            len(s.get("checks", []) if isinstance(s.get("checks"), list) else [])
        ),
        reverse=True
    )


def sort_narratives(narratives: list[dict]):
    if not isinstance(narratives, list):
        return narratives

    return sorted(
        narratives,
        key=lambda n: (
            severity_rank(n.get("severity", "low")),
            len(str(n.get("summary", "")))
        ),
        reverse=True
    )


def replay_result_rank(result: dict) -> int:
    if not isinstance(result, dict):
        return 0

    if result.get("error"):
        return -10

    analysis = safe_get(result, "analysis", {}) or {}
    verdict = str(safe_get(analysis, "verdict", ""))
    flags = safe_get(analysis, "flags", {}) or {}

    score = safe_int(safe_get(analysis, "score", 0), 0)

    rank = 0

    if verdict == "HIGH PROBABILITY IDOR":
        rank += 100
    elif verdict == "POSSIBLE AUTH/OBJECT ISSUE":
        rank += 60
    elif verdict == "AUTH BOUNDARY DIFFERENCE":
        rank += 20

    if safe_get(flags, "successful_cross_object_behavior", False):
        rank += 30
    if safe_get(flags, "sensitive_disclosure_signal", False):
        rank += 25
    if safe_get(flags, "auth_boundary_only", False):
        rank -= 20

    if safe_get(result, "status_changed", False):
        rank += 10
    if safe_get(result, "fingerprint_changed", False):
        rank += 12
    if safe_get(result, "length_changed", False):
        rank += 6

    rank += min(score, 20)

    return rank

def exploit_attempt_rank(result: dict) -> int:
    if not isinstance(result, dict):
        return 0

    rank = 0

    if safe_get(result, "confirmed", False):
        rank += 100
    elif result.get("stable"):
        rank += 50

    rank += safe_int(result.get("strong_hits", 0), 0) * 20
    rank += safe_int(result.get("stable_hits", 0), 0) * 10

    return rank


def sort_mutation_results(results: list[dict]):
    if not isinstance(results, list):
        return results
    return sorted(results, key=replay_result_rank, reverse=True)


def sort_multi_auth_results(results: list[dict]):
    if not isinstance(results, list):
        return results
    return sorted(results, key=replay_result_rank, reverse=True)


def sort_exploit_results(results: list[dict]):
    if not isinstance(results, list):
        return results
    return sorted(results, key=exploit_attempt_rank, reverse=True)


def sort_corroborated_entries(entries: list[dict]):
    if not isinstance(entries, list):
        return entries

    def rank_entry(entry: dict) -> int:
        cmp_result = safe_get(entry, "comparison", {}) or {}
        verdict = str(cmp_result.get("verdict", ""))
        confidence = str(cmp_result.get("confidence", "")).lower()

        rank = 0
        if verdict == "CROSS_USER_OBJECT_VARIANCE":
            rank += 100
        elif verdict == "POSSIBLE_CROSS_USER_ACCESS":
            rank += 70
        elif verdict == "AUTH_BOUNDARY_ONLY":
            rank += 30
        elif verdict == "SHARED_OR_PUBLIC_OBJECT":
            rank += 10

        if confidence == "high":
            rank += 20
        elif confidence == "medium":
            rank += 10

        rank += len(cmp_result.get("reasons", []) or [])
        return rank

    return sorted(entries, key=rank_entry, reverse=True)

def trim_results(results, limit=5):
    if not isinstance(results, list):
        return results
    return results[:limit]



def prepare_output_views(signals, suggestions, narratives, mutation_replay, multi_auth_result, exploit):
    sorted_signals = sort_detection_signals(safe_list(signals))
    sorted_suggestions = sort_exploit_suggestions(safe_list(suggestions))
    sorted_narratives = sort_narratives(safe_list(narratives))

    mutation_view = dict(mutation_replay or {})
    if isinstance(mutation_view.get("results"), list):
        mutation_view["results"] = trim_results(
            sort_mutation_results(mutation_view.get("results", [])),
            limit=5
        )

    multi_auth_view = dict(multi_auth_result or {})
    if isinstance(multi_auth_view.get("results"), list):
        multi_auth_view["results"] = trim_results(
            sort_multi_auth_results(multi_auth_view.get("results", [])),
            limit=5
        )

    if isinstance(multi_auth_view.get("corroborated_differences"), list):
        multi_auth_view["corroborated_differences"] = trim_results(
            sort_corroborated_entries(multi_auth_view.get("corroborated_differences", [])),
            limit=5
        )

    if isinstance(multi_auth_view.get("corroborated_auth_boundaries"), list):
        multi_auth_view["corroborated_auth_boundaries"] = trim_results(
            sort_corroborated_entries(multi_auth_view.get("corroborated_auth_boundaries", [])),
            limit=5
        )

    if isinstance(multi_auth_view.get("corroborated_shared"), list):
        multi_auth_view["corroborated_shared"] = trim_results(
            sort_corroborated_entries(multi_auth_view.get("corroborated_shared", [])),
            limit=5
        )

    exploit_view = dict(exploit or {})
    if isinstance(exploit_view.get("results"), list):
        exploit_view["results"] = trim_results(
            sort_exploit_results(exploit_view.get("results", [])),
            limit=5
        )

    return {
        "signals": sorted_signals,
        "suggestions": sorted_suggestions,
        "narratives": sorted_narratives,
        "mutation_view": mutation_view,
        "multi_auth_view": multi_auth_view,
        "exploit_view": exploit_view
    }

# ============================================
# PRIORITY FINDINGS / EVIDENCE SUMMARY
# ============================================

def build_priority_findings(signals, exploit, multi_auth, corroboration):
    findings = []

    signal_types = {safe_get(s, "type", "") for s in signals if isinstance(s, dict)}

    if "confirmed-exploit" in signal_types:
        findings.append("Confirmed exploit replay behavior")

    if "cross-user-corroborated-object-access" in signal_types:
        findings.append("Cross-user corroborated object access")

    if "multi-auth-same-object-difference" in signal_types:
        findings.append("Same-object cross-profile difference (strong IDOR signal)")

    if "high-probability-idor" in signal_types:
        findings.append("High-probability IDOR via mutation replay")

    if "multi-auth-high-confidence-idor" in signal_types:
        findings.append("High-confidence multi-auth IDOR")

    if "stable-exploit-behavior" in signal_types:
        findings.append("Stable exploit-like replay behavior")

    if (
        "multi-auth-same-object-auth-boundary" in signal_types
        and "multi-auth-same-object-difference" not in signal_types
    ):
        findings.append("Same-object auth-boundary difference needs validation")

    if (
        "mutation-auth-boundary" in signal_types
        and "high-probability-idor" not in signal_types
        and "confirmed-exploit" not in signal_types
    ):
        findings.append("Mutation replay hit auth boundary but did not confirm IDOR")

    if (
        "auth-content-diff" in signal_types
        and not findings
    ):
        findings.append("Authenticated and unauthenticated behavior differs")

    deduped = []
    seen = set()
    for item in findings:
        if item not in seen:
            seen.add(item)
            deduped.append(item)

    return deduped

def build_evidence_summary(mutation, multi_auth, exploit, corroboration):
    return {
        "mutation": {
            "tested": mutation.get("tested_count", 0),
            "meaningful": mutation.get("meaningful_count", 0)
        },
        "multi_auth": {
            "tested": multi_auth.get("tested_count", 0),
            "meaningful": multi_auth.get("meaningful_count", 0),
            "high_confidence": multi_auth.get("high_confidence_count", 0),
            "auth_boundary": multi_auth.get("auth_boundary_count", 0),
            "same_object_difference": multi_auth.get("corroborated_difference_count", 0),
            "same_object_auth_boundary": multi_auth.get("corroborated_auth_boundary_count", 0),
            "same_object_shared": multi_auth.get("corroborated_shared_count", 0)
        },
        "corroboration": {
            "performed": corroboration.get("performed", False),
            "meaningful": corroboration.get("meaningful_count", 0),
            "strong": corroboration.get("strong_finding_count", 0),
            "auth_boundary": corroboration.get("auth_boundary_count", 0),
            "shared": corroboration.get("shared_or_public_count", 0)
        },
        "exploit": {
            "tested": exploit.get("tested", 0),
            "confirmed": exploit.get("confirmed", 0),
            "stable_only": exploit.get("stable_only", 0)
        }
    }

# ============================================
# EXPLOIT NARRATIVE ENGINE
# ============================================

def summarize_field_diff(field_diff: dict, limit: int = 5):
    if not isinstance(field_diff, dict):
        return []

    lines = []

    for item in field_diff.get("changed", [])[:limit]:
        field = item.get("field", "")
        before = item.get("before", "")
        after = item.get("after", "")
        lines.append(f"changed field `{field}` from `{before}` to `{after}`")

    for item in field_diff.get("added", [])[:limit]:
        field = item.get("field", "")
        value = item.get("value", "")
        lines.append(f"added field `{field}` = `{value}`")

    for item in field_diff.get("removed", [])[:limit]:
        field = item.get("field", "")
        lines.append(f"removed field `{field}`")

    return lines[:limit]


def exploit_narrative(path: str, signals: list[dict], mutation_replay: dict,
                      multi_auth_result: dict, exploit: dict, corroboration: dict):
    narratives = []
    signal_types = {s["type"] for s in signals}

    if "confirmed-exploit" in signal_types:
        narratives.append({
            "title": "Confirmed exploit behavior",
            "severity": "critical",
            "summary": (
                f"Replay testing against {path} produced stable repeated behavior "
                f"strong enough to count as confirmed exploit evidence."
            )
        })

    if "cross-user-corroborated-object-access" in signal_types:
        narratives.append({
            "title": "Cross-user corroborated object access",
            "severity": "critical",
            "summary": (
                f"Cross-user corroboration on {path} showed same-object behavioral differences "
                f"across user contexts, which strongly increases confidence in an access-control issue."
            )
        })

    if "multi-auth-same-object-difference" in signal_types:
        for c in multi_auth_result.get("corroborated_differences", [])[:5]:
            cmp_result = c.get("comparison", {}) or {}
            reasons = cmp_result.get("reasons", [])
            reason_text = "; ".join(reasons[:3]) if reasons else "profiles behaved differently on the same mutated object"

            narratives.append({
                "title": "Same-object cross-profile difference",
                "severity": "critical",
                "summary": (
                    f"The same mutated object `{c.get('mutated_url', '')}` behaved differently for "
                    f"`{c.get('profile_a', '')}` vs `{c.get('profile_b', '')}`. {reason_text}."
                )
            })

    if "high-probability-idor" in signal_types:
        for r in mutation_replay.get("results", [])[:5]:
            if r.get("error"):
                continue

            analysis = r.get("analysis", {}) or {}
            verdict = analysis.get("verdict", "")

            if verdict == "HIGH PROBABILITY IDOR":
                extra = summarize_field_diff(analysis.get("field_diff", {}), limit=3)
                summary = (
                    f"Mutation replay changed `{r.get('input_name', '')}` to `{r.get('mutation', '')}` "
                    f"and still returned a successful response, suggesting object-level access drift."
                )
                if extra:
                    summary += " Key differences: " + "; ".join(extra) + "."

                narratives.append({
                    "title": "High-probability mutation-based IDOR",
                    "severity": "high",
                    "summary": summary
                })

    if "stable-exploit-behavior" in signal_types and "confirmed-exploit" not in signal_types:
        narratives.append({
            "title": "Stable replay behavior",
            "severity": "medium",
            "summary": (
                f"Replay testing against {path} was repeatable, but evidence is not yet "
                f"strong enough to classify as fully confirmed exploit behavior."
            )
        })

    if "multi-auth-same-object-auth-boundary" in signal_types and "multi-auth-same-object-difference" not in signal_types:
        for c in multi_auth_result.get("corroborated_auth_boundaries", [])[:5]:
            narratives.append({
                "title": "Same-object auth boundary",
                "severity": "medium",
                "summary": (
                    f"The same mutated object `{c.get('mutated_url', '')}` was allowed for one profile "
                    f"and denied for another. This may be correct ownership enforcement, but should be validated."
                )
            })

    if "mutation-auth-boundary" in signal_types and "high-probability-idor" not in signal_types:
        for r in mutation_replay.get("results", [])[:5]:
            if r.get("error"):
                continue

            analysis = r.get("analysis", {}) or {}
            flags = analysis.get("flags", {}) or {}
            if flags.get("auth_boundary_only"):
                narratives.append({
                    "title": "Mutation reached auth boundary",
                    "severity": "medium",
                    "summary": (
                        f"Mutation replay for `{r.get('input_name', '')}` -> `{r.get('mutation', '')}` "
                        f"changed behavior, but current evidence looks more like denial/boundary enforcement "
                        f"than successful cross-object access."
                    )
                })

    if "multi-auth-same-object-shared" in signal_types:
        for c in multi_auth_result.get("corroborated_shared", [])[:3]:
            narratives.append({
                "title": "Same-object shared/public behavior",
                "severity": "low",
                "summary": (
                    f"The same mutated object `{c.get('mutated_url', '')}` looked materially similar across "
                    f"`{c.get('profile_a', '')}` and `{c.get('profile_b', '')}`, suggesting shared or public behavior."
                )
            })

    if not narratives:
        narratives.append({
            "title": "No strong exploit narrative yet",
            "severity": "low",
            "summary": (
                f"No single exploit narrative dominates for {path} yet. Continue validating object ownership, "
                f"auth boundaries, and same-object behavior across profiles."
            )
        })

    return narratives

def strongest_narrative(narratives: list[dict]):
    if not narratives:
        return None

    rank = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1
    }

    ordered = sorted(
        narratives,
        key=lambda x: rank.get(x.get("severity", "low"), 1),
        reverse=True
    )
    return ordered[0]


# ============================================
# REPORT-READY FINDING OBJECTS
# ============================================

def finding_confidence_from_signals(signal_types: set[str]) -> str:
    if (
        "confirmed-exploit" in signal_types
        or "cross-user-corroborated-object-access" in signal_types
        or "multi-auth-same-object-difference" in signal_types
    ):
        return "high"

    if (
        "high-probability-idor" in signal_types
        or "multi-auth-high-confidence-idor" in signal_types
        or "stable-exploit-behavior" in signal_types
    ):
        return "medium"

    return "low"


def finding_severity_from_signals(signal_types: set[str]) -> str:
    if (
        "confirmed-exploit" in signal_types
        or "cross-user-corroborated-object-access" in signal_types
        or "multi-auth-same-object-difference" in signal_types
    ):
        return "critical"

    if (
        "high-probability-idor" in signal_types
        or "multi-auth-high-confidence-idor" in signal_types
    ):
        return "high"

    if (
        "stable-exploit-behavior" in signal_types
        or "auth-content-diff" in signal_types
        or "multi-auth-auth-boundary" in signal_types
    ):
        return "medium"

    return "low"


def finding_category_from_signals(signal_types: set[str]) -> str:
    if (
        "high-probability-idor" in signal_types
        or "multi-auth-high-confidence-idor" in signal_types
        or "cross-user-corroborated-object-access" in signal_types
        or "multi-auth-same-object-difference" in signal_types
    ):
        return "idor-access-control"

    if "confirmed-exploit" in signal_types:
        return "confirmed-exploit"

    if "multi-auth-auth-boundary" in signal_types:
        return "authorization-boundary"

    return "general"


def build_finding_title(path: str, signal_types: set[str]) -> str:
    if "cross-user-corroborated-object-access" in signal_types:
        return f"Cross-user corroborated object access issue on {path}"

    if "multi-auth-same-object-difference" in signal_types:
        return f"Same-object cross-profile access difference on {path}"

    if "confirmed-exploit" in signal_types:
        return f"Confirmed exploit behavior on {path}"

    if "high-probability-idor" in signal_types:
        return f"High-probability IDOR on {path}"

    if "multi-auth-high-confidence-idor" in signal_types:
        return f"High-confidence multi-auth IDOR on {path}"

    if "stable-exploit-behavior" in signal_types:
        return f"Stable exploit-like behavior on {path}"

    return f"Suspicious authorization behavior on {path}"


def build_finding_summary(path: str, signal_types: set[str], risk_score: int) -> str:
    if "cross-user-corroborated-object-access" in signal_types:
        return (
            f"The endpoint {path} showed same-object behavioral differences across user contexts, "
            f"which strongly suggests object-level authorization weakness."
        )

    if "multi-auth-same-object-difference" in signal_types:
        return (
            f"The same mutated object on {path} behaved differently across profiles, which is stronger "
            f"than ordinary session drift and supports an access-control finding."
        )

    if "confirmed-exploit" in signal_types:
        return (
            f"Replay testing against {path} produced stable repeated exploit-like behavior with a "
            f"risk score of {risk_score}."
        )

    if "high-probability-idor" in signal_types or "multi-auth-high-confidence-idor" in signal_types:
        return (
            f"Testing against {path} produced strong object-access signals consistent with an IDOR-style issue."
        )

    if "stable-exploit-behavior" in signal_types:
        return (
            f"Replay testing against {path} was stable and suspicious, but not yet strong enough for full confirmation."
        )

    return f"The endpoint {path} showed suspicious access-control-related behavior worth manual validation."

def build_finding_impact(signal_types: set[str]) -> str:
    if (
        "cross-user-corroborated-object-access" in signal_types
        or "multi-auth-same-object-difference" in signal_types
    ):
        return (
            "An attacker may be able to access or distinguish another user's object data, "
            "which can lead to unauthorized disclosure of business-sensitive or ownership-sensitive information."
        )

    if (
        "high-probability-idor" in signal_types
        or "multi-auth-high-confidence-idor" in signal_types
    ):
        return (
            "If validated, this could allow unauthorized access to object data by manipulating identifiers "
            "or replaying requests under alternate authenticated contexts."
        )

    if "confirmed-exploit" in signal_types:
        return (
            "Repeated exploit-like behavior suggests the issue may be reproducible and suitable for report-quality validation."
        )

    return "Impact is not yet fully established and needs manual confirmation."


def collect_finding_evidence(path: str, mutation_replay: dict, multi_auth_result: dict,
                             exploit: dict, corroboration: dict, limit: int = 8):
    evidence = []

    for r in safe_list(safe_get(mutation_replay, "results", [])):
        if not isinstance(r, dict):
            continue
        if len(evidence) >= limit:
            break
        if r.get("error"):
            continue

        analysis = safe_get(r, "analysis", {}) or {}
        verdict = safe_get(analysis, "verdict", "")
        if verdict in {"HIGH PROBABILITY IDOR", "POSSIBLE AUTH/OBJECT ISSUE"}:
            evidence.append({
                "type": "mutation-replay",
                "input_name": safe_get(r, "input_name"),
                "mutation": safe_get(r, "mutation"),
                "url": safe_get(r, "mutated_url"),
                "status_code": safe_get(r, "status_code"),
                "verdict": verdict,
                "score": safe_get(analysis, "score", 0)
            })

        flags = safe_get(analysis, "flags", {}) or {}
        if safe_get(flags, "auth_boundary_only", False):
            evidence.append({
                "type": "mutation-auth-boundary",
                "input_name": safe_get(r, "input_name"),
                "mutation": safe_get(r, "mutation"),
                "url": safe_get(r, "mutated_url"),
                "status_code": safe_get(r, "status_code"),
                "verdict": safe_get(analysis, "verdict", ""),
                "reasons": safe_list(safe_get(analysis, "reasons", []))[:4]
            })

        if len(evidence) >= limit:
            break

    for r in safe_list(safe_get(multi_auth_result, "corroborated_differences", []))[:limit]:
        if not isinstance(r, dict):
            continue
        if len(evidence) >= limit:
            break

        cmp_result = safe_get(r, "comparison", {}) or {}
        evidence.append({
            "type": "multi-auth-corroboration",
            "url": safe_get(r, "mutated_url"),
            "profile_a": safe_get(r, "profile_a"),
            "profile_b": safe_get(r, "profile_b"),
            "verdict": safe_get(cmp_result, "verdict"),
            "confidence": safe_get(cmp_result, "confidence"),
            "reasons": safe_list(safe_get(cmp_result, "reasons", []))
        })

    for r in safe_list(safe_get(exploit, "results", []))[:limit]:
        if not isinstance(r, dict):
            continue
        if len(evidence) >= limit:
            break
        if safe_get(r, "confirmed", False):
            evidence.append({
                "type": "exploit-replay",
                "target": safe_get(r, "target"),
                "confirmed": safe_get(r, "confirmed"),
                "stable_hits": safe_get(r, "stable_hits", 0),
                "strong_hits": safe_get(r, "strong_hits", 0)
            })

    if safe_get(corroboration, "strong_finding_count", 0) > 0 and len(evidence) < limit:
        evidence.append({
            "type": "cross-user-corroboration-summary",
            "strong_finding_count": safe_get(corroboration, "strong_finding_count", 0),
            "auth_boundary_count": safe_get(corroboration, "auth_boundary_count", 0),
            "shared_or_public_count": safe_get(corroboration, "shared_or_public_count", 0)
        })

    return evidence[:limit]

def build_reproduction_notes(path: str, signal_types: set[str]):
    notes = []

    notes.append(f"Start from the observed endpoint: {path}.")
    notes.append("Replay the original authenticated request and preserve the baseline response.")

    if (
        "high-probability-idor" in signal_types
        or "multi-auth-high-confidence-idor" in signal_types
        or "multi-auth-same-object-difference" in signal_types
    ):
        notes.append("Change the identifier-like value to a neighboring or alternate object reference.")
        notes.append("Compare status, response body shape, ownership fields, and business-sensitive fields.")
        notes.append("Repeat using at least two authenticated profiles when available.")

    if "confirmed-exploit" in signal_types:
        notes.append("Repeat the strongest replay multiple times to confirm stable reproducibility.")

    if "cross-user-corroborated-object-access" in signal_types:
        notes.append("Preserve same-object request/response pairs across distinct authenticated users.")

    if "multi-auth-same-object-auth-boundary" in signal_types:
        notes.append("Verify whether denial for one user and success for another is expected ownership enforcement.")

    return notes

def build_report_ready_findings(path: str, risk_score: int, signals: list[dict],
                                mutation_replay: dict, multi_auth_result: dict,
                                exploit: dict, corroboration: dict):
    signal_types = {s["type"] for s in signals}

    # Do not report findings for empty/null responses
    if "empty-or-null-response" in signal_types:
        return []  # or return a low‑severity informational item if you prefer

    high_value = (
        "confirmed-exploit" in signal_types
        or "cross-user-corroborated-object-access" in signal_types
        or "multi-auth-same-object-difference" in signal_types
        or "high-probability-idor" in signal_types
        or "multi-auth-high-confidence-idor" in signal_types
        or "stable-exploit-behavior" in signal_types
        or "multi-auth-same-object-auth-boundary" in signal_types
    )

    findings = []
    if high_value:
        findings.append({
            "title": build_finding_title(path, signal_types),
            "severity": finding_severity_from_signals(signal_types),
            "confidence": finding_confidence_from_signals(signal_types),
            "category": finding_category_from_signals(signal_types),
            "summary": build_finding_summary(path, signal_types, risk_score),
            "impact": build_finding_impact(signal_types),
            "evidence": collect_finding_evidence(
                path=path,
                mutation_replay=mutation_replay,
                multi_auth_result=multi_auth_result,
                exploit=exploit,
                corroboration=corroboration
            ),
            "reproduction_notes": build_reproduction_notes(path, signal_types)
        })

    if not findings:
        findings.append({
            "title": f"Suspicious behavior on {path}",
            "severity": "low",
            "confidence": "low",
            "category": "general",
            "summary": "The endpoint produced signals worth manual review, but no report-ready high-confidence finding is established yet.",
            "impact": "Impact is not yet established.",
            "evidence": [],
            "reproduction_notes": [
                f"Replay the original request for {path}.",
                "Test identifier-like values carefully within authorized scope.",
                "Compare authenticated, unauthenticated, and alternate-profile behavior where available."
            ]
        })

    return findings


def sort_report_findings(findings: list[dict]):
    if not isinstance(findings, list):
        return findings

    confidence_rank = {
        "high": 3,
        "medium": 2,
        "low": 1
    }

    category_rank = {
        "confirmed-exploit": 4,
        "idor-access-control": 3,
        "authorization-boundary": 2,
        "general": 1
    }

    return sorted(
        findings,
        key=lambda f: (
            severity_rank(f.get("severity", "low")),
            confidence_rank.get(str(f.get("confidence", "low")).lower(), 1),
            category_rank.get(str(f.get("category", "general")).lower(), 1),
            len(f.get("evidence", []) if isinstance(f.get("evidence"), list) else [])
        ),
        reverse=True
    )

#--------------------------------------------
# FUZZING HINTS
# ============================================

def fuzzing_hints(params, graph=None):
    hints = []

    if any(p["classification"] == "id-like" for p in params):
        hints.append("Try incrementing and decrementing identifier-like values within authorized scope.")

    if any(p["classification"] == "role" for p in params):
        hints.append("Try role-like value changes and compare whether the server enforces privilege server-side.")

    if any(p["classification"] == "identity" for p in params):
        hints.append("Try identity-like swaps and compare whether ownership is derived from the session or trusted from input.")

    if graph is not None:
        families = graph_object_families(graph)
        if families:
            hints.append("Pivot across related object-family endpoints: " + ", ".join(families))

        patterns = graph_related_endpoint_patterns(graph)
        if patterns:
            hints.append("Compare authorization consistency across related endpoint patterns: " + ", ".join(patterns[:6]))

        persistent_edges = graph.get("persistent_edge_memory", [])
        if persistent_edges:
            hints.append("Prioritize recurring linked objects from graph memory when choosing pivots.")

    if not hints:
        hints.append("Try null, empty, duplicate, and type-shift mutations.")

    return hints


# ============================================
# EXPLOIT SUGGESTIONS
# ============================================

def exploit_suggestions(signals):
    suggestions = []

    signal_types = {s["type"] for s in signals}

    has_confirmed = "confirmed-exploit" in signal_types
    has_stable_exploit = "stable-exploit-behavior" in signal_types
    has_high_idor = "high-probability-idor" in signal_types
    has_multi_auth_high = "multi-auth-high-confidence-idor" in signal_types
    has_cross_user_diff = "cross-user-corroboration-diff" in signal_types
    has_cross_user_object = "cross-user-corroborated-object-access" in signal_types

    has_multi_auth_same_object_diff = "multi-auth-same-object-difference" in signal_types
    has_multi_auth_same_object_boundary = "multi-auth-same-object-auth-boundary" in signal_types
    has_multi_auth_same_object_shared = "multi-auth-same-object-shared" in signal_types

    has_object_surface = (
        "object-reference-surface" in signal_types
        or "path-object-surface" in signal_types
    )
    has_auth_diff = (
        "auth-content-diff" in signal_types
        or "auth-length-diff" in signal_types
    )

    auth_boundary_only = (
        has_auth_diff
        and not has_confirmed
        and not has_high_idor
        and not has_multi_auth_high
        and not has_cross_user_object
        and not has_multi_auth_same_object_diff
    )

    if has_object_surface:
        suggestions.append({
            "title": "Object reference authorization check",
            "priority": "high",
            "category": "access-control",
            "why": "The endpoint exposes identifier-like object access surface that may be vulnerable to weak ownership enforcement or IDOR.",
            "checks": [
                "Compare access to your own object versus another object in authorized scope.",
                "Try neighboring identifiers and compare status, response length, and returned fields.",
                "Check whether object read endpoints and action endpoints enforce ownership consistently."
            ]
        })

    if has_multi_auth_high or "multi-auth-diff" in signal_types:
        suggestions.append({
            "title": "Cross-account authorization comparison",
            "priority": "high",
            "category": "multi-auth",
            "why": "Different auth profiles produced different behavior for related object requests.",
            "checks": [
                "Compare which account or profile can access which object IDs.",
                "Look for successful responses under alternate auth where access should fail.",
                "Check whether field-level disclosure differs across accounts."
            ]
        })

    if has_multi_auth_same_object_diff:
        suggestions.append({
            "title": "Same-object cross-profile validation",
            "priority": "high",
            "category": "multi-auth-corroboration",
            "why": "The same mutated object behaved differently across profiles, which is stronger than general multi-auth drift.",
            "checks": [
                "Preserve requests for the exact same object under each profile.",
                "Compare ownership markers, business data, and sensitive fields across profiles.",
                "Prioritize same-object evidence over broad session-to-session differences."
            ]
        })

    if has_multi_auth_same_object_boundary and not has_multi_auth_same_object_diff:
        suggestions.append({
            "title": "Same-object auth-boundary review",
            "priority": "medium",
            "category": "multi-auth-boundary",
            "why": "The same object was denied for one profile and allowed for another, which may reflect correct enforcement or an ownership boundary worth validating.",
            "checks": [
                "Check whether the denied profile truly should not access that object.",
                "Confirm whether object ownership explains the difference cleanly.",
                "Look for inconsistent cases where similarly positioned users get different decisions."
            ]
        })

    if has_multi_auth_same_object_shared:
        suggestions.append({
            "title": "Shared-object validation",
            "priority": "low",
            "category": "shared-surface",
            "why": "The same object looked similar across profiles and may be intentionally shared or public.",
            "checks": [
                "Confirm whether the object is meant to be public or cross-user visible.",
                "Avoid escalating shared/public behavior unless sensitive data differs.",
                "Check whether related non-public fields stay properly protected."
            ]
        })

    if has_cross_user_diff or has_cross_user_object:
        suggestions.append({
            "title": "Cross-user corroboration review",
            "priority": "high",
            "category": "cross-user-validation",
            "why": "The same object mutation appears to behave differently across user contexts, which is stronger than a simple single-session mutation signal.",
            "checks": [
                "Validate the exact same object ID across at least two distinct authenticated users.",
                "Capture whether the same mutated object returns materially different body content, ownership fields, or business data across users.",
                "Prioritize same-object comparisons over general profile-to-profile drift."
            ]
        })

    if has_high_idor:
        suggestions.append({
            "title": "High-probability IDOR validation",
            "priority": "high",
            "category": "idor",
            "why": "Mutation replay produced high-confidence object-access signals beyond simple authentication failure.",
            "checks": [
                "Manually validate the strongest mutation with valid authorization.",
                "Capture object ownership differences across responses.",
                "Check whether related endpoints reuse the same object family without proper authorization."
            ]
        })

    if has_confirmed:
        suggestions.append({
            "title": "Confirmed exploit follow-up",
            "priority": "high",
            "category": "exploit-confirmation",
            "why": "The exploit replay engine found stable repeated successful behavior suggesting a real issue.",
            "checks": [
                "Re-run the confirmed sequence manually to validate reproducibility.",
                "Capture evidence of changed status, fingerprint, and sensitive field differences.",
                "Check whether the confirmed issue extends to related object-family endpoints."
            ]
        })

    if has_stable_exploit and not has_confirmed:
        suggestions.append({
            "title": "Stable replay evidence review",
            "priority": "medium",
            "category": "replay-validation",
            "why": "Replay behavior was repeatable, but current evidence is not yet strong enough to call it a confirmed exploit.",
            "checks": [
                "Review whether repeated differences reflect real cross-object access or only generalized response drift.",
                "Focus on ownership-sensitive fields, business data, and successful object access under valid auth.",
                "Promote to confirmed only when repeated replays preserve strong exploit indicators."
            ]
        })

    if has_confirmed and has_cross_user_object:
        suggestions.append({
            "title": "Corroborated object-access evidence pack",
            "priority": "high",
            "category": "evidence-hardening",
            "why": "The finding has both replay stability and same-object cross-user corroboration, making it much stronger for manual validation and reporting.",
            "checks": [
                "Preserve request and response pairs for the same object under each user context.",
                "Document stable replay evidence separately from cross-user content differences.",
                "Highlight ownership-sensitive fields and business impact, not just status-code changes."
            ]
        })

    if auth_boundary_only:
        suggestions.append({
            "title": "Authorization boundary review",
            "priority": "medium",
            "category": "auth-boundary",
            "why": "The endpoint clearly changes behavior across authentication states, but current evidence points to access denial rather than confirmed cross-object access.",
            "checks": [
                "Verify whether the server consistently denies unauthorized access for neighboring object IDs.",
                "Retest with known-valid alternate user credentials instead of missing or invalid tokens.",
                "Look for cases where object IDs succeed under the wrong authenticated identity, not just where unauthenticated requests fail."
            ]
        })

    if "business-endpoint" in signal_types:
        suggestions.append({
            "title": "Business workflow integrity review",
            "priority": "medium",
            "category": "business-logic",
            "why": "The endpoint appears business-relevant and may be part of a multi-step workflow.",
            "checks": [
                "Compare read-only versus action or workflow enforcement for the same object family.",
                "Try replaying stale or cross-user object references inside workflow endpoints.",
                "Check whether validation changes across the same family of routes."
            ]
        })

    if not suggestions:
        suggestions.append({
            "title": "Baseline authorized validation",
            "priority": "low",
            "category": "general",
            "why": "No strong exploit-oriented signal has been confirmed yet, but the endpoint still has review value.",
            "checks": [
                "Compare authenticated and unauthenticated behavior.",
                "Try low-risk identifier, null, and type-shift mutations.",
                "Look for differences in body shape, not just status code."
            ]
        })

    return suggestions

#---------------------------------------------
# LEADERBOARD
#---------------------------------------------

def leaderboard(program: str = "local-lab"):
    conn = get_db()
    rows = conn.execute("""
        SELECT path, method, COUNT(*) as hits
        FROM observations
        WHERE program = ?
        GROUP BY path, method
        ORDER BY hits DESC
        LIMIT 10
    """, (program,)).fetchall()
    conn.close()

    return [{"path": r["path"], "method": r["method"], "hits": r["hits"]} for r in rows]


# ============================================
# INGEST STAGE HELPERS
# ============================================

def parse_ingest_request(data: dict):
    program = data.get("program", "local-lab")
    method = str(data.get("method", "GET")).upper()
    url = data.get("url", "")
    headers = data.get("headers", {}) or {}
    body = data.get("body", "") or ""
    response_text = data.get("response", "") or ""
    status_code = int(data.get("status_code", 0) or 0)
    payload_multi_auth_profiles = data.get("multi_auth_profiles", []) or []

    path = extract_path(url)
    query = extract_query(url)
    auth_state = detect_auth(headers)

    return {
        "program": program,
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "response_text": response_text,
        "status_code": status_code,
        "payload_multi_auth_profiles": payload_multi_auth_profiles,
        "path": path,
        "query": query,
        "auth_state": auth_state
    }

def build_current_response_state(response_text: str, status_code: int):
    return {
        "status_code": status_code,
        "length": len(response_text),
        "fingerprint": stable_fingerprint(response_text),
        "raw_fingerprint": fp(response_text),
        "response_text": response_text,
        "fields": response_json_fields(response_text),
        "normalized_fields": normalized_response_fields(response_text)
    }

def build_candidate_inputs(url: str, headers: dict, body: str):
    all_params = extract_candidate_inputs(url, headers, body)
    for p in all_params:
        p["mutation_presets"] = mutation_presets_for_input(p)
    return all_params

def run_replay_stages(
    trace_id: str,
    program: str,
    path: str,
    url: str,
    method: str,
    headers: dict,
    body: str,
    current: dict,
    all_params: list[dict],
    payload_multi_auth_profiles: list
):
    timings = {}

    meaningful_inputs = meaningful_candidate_inputs(all_params)
    replay_allowed = should_attempt_auto_replay(method, url, all_params)

    if not replay_allowed:
        replay = {
            "performed": False,
            "skipped": True,
            "reason": "request not replay-worthy"
        }
        mutation_replay = {
            "performed": False,
            "reason": "request not replay-worthy"
        }
        multi_auth_result = {
            "performed": False,
            "reason": "request not replay-worthy"
        }

        log_event(
            "debug",
            trace_id,
            "replay_skipped",
            path=path,
            reason="request not replay-worthy",
            meaningful_input_count=len(meaningful_inputs)
        )

        return {
            "replay": replay,
            "mutation_replay": mutation_replay,
            "multi_auth_result": multi_auth_result,
            "timings": timings
        }

    t0 = now_ms()
    replay = auto_replay(url, method, headers, body, program=program)
    timings["auto_replay_ms"] = elapsed_ms(t0)

    if replay.get("error"):
        log_event(
            "warning",
            trace_id,
            "auto_replay_failed",
            error=replay.get("error"),
            error_kind=replay.get("error_kind"),
            path=path
        )

    t1 = now_ms()
    mutation_replay = auto_mutation_replay(
        url=url,
        method=method,
        headers=headers,
        body=body,
        current=current,
        candidate_inputs=all_params,
        program=program
    )
    timings["auto_mutation_replay_ms"] = elapsed_ms(t1)

    if mutation_replay.get("performed") and mutation_replay.get("meaningful_count", 0) > 0:
        log_event(
            "info",
            trace_id,
            "mutation_replay_meaningful",
            meaningful_count=mutation_replay.get("meaningful_count", 0),
            tested_count=mutation_replay.get("tested_count", 0),
            path=path
        )

    t2 = now_ms()
    multi_auth_result = multi_auth_replay(
        url=url,
        method=method,
        headers=headers,
        body=body,
        current=current,
        candidate_inputs=all_params,
        payload_profiles=payload_multi_auth_profiles,
        program=program
    )
    timings["auto_multi_auth_replay_ms"] = elapsed_ms(t2)

    if multi_auth_result.get("performed") and multi_auth_result.get("meaningful_count", 0) > 0:
        log_event(
            "info",
            trace_id,
            "multi_auth_replay_meaningful",
            meaningful_count=multi_auth_result.get("meaningful_count", 0),
            high_confidence_count=multi_auth_result.get("high_confidence_count", 0),
            path=path
        )

    return {
        "replay": replay,
        "mutation_replay": mutation_replay,
        "multi_auth_result": multi_auth_result,
        "timings": timings
    }

def build_graph_and_context(
    program: str,
    path: str,
    method: str,
    history: list[dict],
    all_params: list[dict],
    base_signals: list[dict]
):
    graph = endpoint_intelligence_graph(
        path=path,
        method=method,
        candidate_inputs=all_params,
        history=history,
        signals=base_signals
    )

    graph = enrich_graph_with_persistent_memory(program, graph)

    related_history = graph_history_similarity(
        current_path=path,
        current_method=method,
        program=program
    )

    return {
        "graph": graph,
        "related_history": related_history
    }


def build_attack_chain_context(
    path: str,
    method: str,
    graph: dict,
    signals: list[dict],
    base_suggestions: list[dict],
    related_history: list[dict]
):
    chain_seed = build_attack_chain_seed(
        path=path,
        method=method,
        graph=graph,
        signals=signals,
        suggestions=base_suggestions
    )

    attack_chain = build_attack_chain(
        seed=chain_seed,
        graph=graph,
        related_history=related_history
    )

    return attack_chain



def run_analysis_stage(
    trace_id: str,
    program: str,
    path: str,
    method: str,
    url: str,
    headers: dict,
    body: str,
    current: dict,
    all_params: list[dict],
    history: list[dict],
    replay: dict,
    mutation_replay: dict,
    multi_auth_result: dict,
    payload_multi_auth_profiles: list
):
    timings = {}

    # ---------------------------------
    # Initial signal build from raw replay data
    # ---------------------------------
    t0 = now_ms()
    diff = compute_diff(current, replay, history)

    initial_signals = detection_signals(
        path=path,
        params=all_params,
        diff=diff,
        mutation=mutation_replay,
        multi_auth=multi_auth_result,
        exploit={"confirmed": 0, "stable_only": 0},
        corroboration={"performed": False, "meaningful_count": 0, "strong_finding_count": 0}
    )
    timings["initial_signal_build_ms"] = elapsed_ms(t0)

    # ---------------------------------
    # Graph context
    # ---------------------------------
    t1 = now_ms()
    graph_context = build_graph_and_context(
        program=program,
        path=path,
        method=method,
        history=history,
        all_params=all_params,
        base_signals=initial_signals
    )

    graph = graph_context["graph"]
    related_history = graph_context["related_history"]
    timings["graph_context_ms"] = elapsed_ms(t1)

    # ---------------------------------
    # Graph-enriched signal/suggestion baseline
    # ---------------------------------
    t2 = now_ms()
    signals = augment_signals_with_graph(
        signals=initial_signals,
        graph=graph,
        related_history=related_history
    )
    signals = augment_signals_with_persistent_graph_memory(signals, graph)

    risk_score, reasons = compute_risk(signals)
    fuzzing = fuzzing_hints(all_params, graph)
    base_suggestions = exploit_suggestions(signals)
    timings["signal_enrichment_ms"] = elapsed_ms(t2)

    # ---------------------------------
    # Attack chain
    # ---------------------------------
    t3 = now_ms()
    attack_chain = build_attack_chain_context(
        path=path,
        method=method,
        graph=graph,
        signals=signals,
        base_suggestions=base_suggestions,
        related_history=related_history
    )
    timings["attack_chain_ms"] = elapsed_ms(t3)

    # ---------------------------------
    # True cross-user corroboration
    # ---------------------------------
    t4 = now_ms()
    corroboration = true_cross_user_corroboration(
        url=url,
        method=method,
        headers=headers,
        body=body,
        current=current,
        candidate_inputs=all_params,
        payload_profiles=payload_multi_auth_profiles,
        program=program
    )
    timings["true_cross_user_corroboration_ms"] = elapsed_ms(t4)

    if corroboration.get("performed") and corroboration.get("strong_finding_count", 0) > 0:
        log_event(
            "info",
            trace_id,
            "true_cross_user_corroboration_strong",
            strong_finding_count=corroboration.get("strong_finding_count", 0),
            path=path
        )
    elif corroboration.get("performed"):
        log_event(
            "debug",
            trace_id,
            "true_cross_user_corroboration_completed",
            meaningful_count=corroboration.get("meaningful_count", 0),
            auth_boundary_count=corroboration.get("auth_boundary_count", 0),
            shared_or_public_count=corroboration.get("shared_or_public_count", 0),
            path=path
        )

    # ---------------------------------
    # Auto exploit replay
    # ---------------------------------
    t5 = now_ms()
    exploit = auto_exploit_replay(
        url=url,
        method=method,
        headers=headers,
        body=body,
        current=current,
        mutation_replay=mutation_replay,
        multi_auth_result=multi_auth_result,
        graph=graph,
        payload_profiles=payload_multi_auth_profiles,
        attack_chain=attack_chain,
        program=program
    )
    timings["auto_exploit_replay_ms"] = elapsed_ms(t5)

    if exploit.get("performed"):
        log_event(
            "info",
            trace_id,
            "auto_exploit_replay_completed",
            tested=exploit.get("tested", 0),
            confirmed=exploit.get("confirmed", 0),
            stable_only=exploit.get("stable_only", 0),
            path=path
        )
    else:
        log_event(
            "debug",
            trace_id,
            "auto_exploit_replay_skipped",
            reason=exploit.get("reason", ""),
            path=path
        )

    # ---------------------------------
    # Final enriched signals
    # ---------------------------------
    t6 = now_ms()
    final_base_signals = detection_signals(
        path=path,
        params=all_params,
        diff=diff,
        mutation=mutation_replay,
        multi_auth=multi_auth_result,
        exploit=exploit,
        corroboration=corroboration
    )

    final_signals = augment_signals_with_graph(
        signals=final_base_signals,
        graph=graph,
        related_history=related_history
    )
    final_signals = augment_signals_with_persistent_graph_memory(final_signals, graph)
    final_signals = augment_signals_with_attack_chain(final_signals, attack_chain)

    final_risk_score, final_reasons = compute_risk(final_signals)

    suggestions = exploit_suggestions(final_signals)
    suggestions = augment_exploit_suggestions_with_graph(
        suggestions=suggestions,
        graph=graph,
        related_history=related_history
    )
    suggestions = augment_exploit_suggestions_with_persistent_graph_memory(
        suggestions=suggestions,
        graph=graph
    )
    suggestions = augment_exploit_suggestions_with_attack_chain(
        suggestions=suggestions,
        chain=attack_chain
    )
    timings["final_enrichment_ms"] = elapsed_ms(t6)

    # ---------------------------------
    # Narratives + report-ready findings
    # ---------------------------------
    narratives = exploit_narrative(
        path=path,
        signals=final_signals,
        mutation_replay=mutation_replay,
        multi_auth_result=multi_auth_result,
        exploit=exploit,
        corroboration=corroboration
    )

    top_narrative = strongest_narrative(narratives)

    output_views = prepare_output_views(
        signals=final_signals,
        suggestions=suggestions,
        narratives=narratives,
        mutation_replay=mutation_replay,
        multi_auth_result=multi_auth_result,
        exploit=exploit
    )

    sorted_signals = output_views["signals"]
    sorted_suggestions = output_views["suggestions"]
    sorted_narratives = output_views["narratives"]
    mutation_output = output_views["mutation_view"]
    multi_auth_output = output_views["multi_auth_view"]
    exploit_output = output_views["exploit_view"]

    top_narrative = strongest_narrative(sorted_narratives)

    priority_findings = build_priority_findings(
        sorted_signals,
        exploit_output,
        multi_auth_output,
        corroboration
    )

    evidence_summary = build_evidence_summary(
        mutation_output,
        multi_auth_output,
        exploit_output,
        corroboration
    )

    report_findings = build_report_ready_findings(
        path=path,
        risk_score=final_risk_score,
        signals=sorted_signals,
        mutation_replay=mutation_output,
        multi_auth_result=multi_auth_output,
        exploit=exploit_output,
        corroboration=corroboration
    )
    report_findings = sort_report_findings(report_findings)

    return {
        "diff": diff,
        "graph": graph,
        "related_history": related_history,
        "fuzzing": fuzzing,
        "base_suggestions": base_suggestions,
        "attack_chain": attack_chain,
        "corroboration": corroboration,
        "exploit": exploit,
        "exploit_output": exploit_output,
        "mutation_output": mutation_output,
        "multi_auth_output": multi_auth_output,
        "signals": final_signals,
        "sorted_signals": sorted_signals,
        "risk_score": final_risk_score,
        "reasons": final_reasons,
        "suggestions": suggestions,
        "sorted_suggestions": sorted_suggestions,
        "narratives": narratives,
        "sorted_narratives": sorted_narratives,
        "top_narrative": top_narrative,
        "priority_findings": priority_findings,
        "evidence_summary": evidence_summary,
        "report_findings": report_findings,
        "timings": timings
    }

# ============================================
# FINAL RESPONSE CONSISTENCY
# ============================================

def validate_analysis_bundle(bundle: dict):
    required_keys = [
        "diff",
        "graph",
        "related_history",
        "fuzzing",
        "attack_chain",
        "corroboration",
        "exploit",
        "exploit_output",
        "mutation_output",
        "multi_auth_output",
        "signals",
        "sorted_signals",
        "risk_score",
        "reasons",
        "suggestions",
        "sorted_suggestions",
        "narratives",
        "sorted_narratives",
        "top_narrative",
        "priority_findings",
        "evidence_summary",
        "report_findings",
        "timings"
    ]

    missing = [k for k in required_keys if k not in bundle]
    return {
        "ok": len(missing) == 0,
        "missing": missing
    }

# ============================================
# PIVOT ENGINE
# ============================================

PIVOT_DEFAULT_LIMIT = 5
PIVOT_ACTION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
PIVOT_SAFE_METHODS = {"GET", "HEAD"}
PIVOT_MAX_BODY_PREVIEW = 4000


def parse_neighbor_target(target: str):
    """
    Accepts:
      'POST /rest/basket/3/checkout'
      'GET /rest/basket/0'
      '/api/basket/{id}'
    """
    text = str(target or "").strip()
    if not text:
        return {"method": "GET", "path": ""}

    parts = text.split(" ", 1)
    if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
        return {"method": parts[0].upper(), "path": parts[1].strip()}

    return {"method": "GET", "path": text}


def extract_seed_object_value(candidate_inputs: list):
    for item in candidate_inputs or []:
        if item.get("classification") == "id-like":
            return str(item.get("sample_value") or item.get("value") or "").strip()
    return ""


def best_confirmed_mutation_values(mutation_output: dict, exploit_output: dict, limit: int = 3):
    ranked = []

    exploit_by_url = {}
    for item in exploit_output.get("results", []) or []:
        if not isinstance(item, dict):
            continue
        exploit_by_url[item.get("target", "")] = item

    for r in mutation_output.get("results", []) or []:
        if not isinstance(r, dict):
            continue
        if r.get("error"):
            continue

        analysis = r.get("analysis", {}) or {}
        verdict = str(analysis.get("verdict", ""))
        score = int(analysis.get("score", 0) or 0)
        target = r.get("mutated_url", "")
        exploit = exploit_by_url.get(target, {}) or {}

        rank = 0
        if verdict == "HIGH PROBABILITY IDOR":
            rank += 100
        rank += score
        if exploit.get("confirmed"):
            rank += 100
        elif exploit.get("stable"):
            rank += 40

        ranked.append({
            "mutation": str(r.get("mutation", "")),
            "url": target,
            "rank": rank,
            "status_code": r.get("status_code"),
            "verdict": verdict
        })

    ranked.sort(key=lambda x: x["rank"], reverse=True)

    seen = set()
    values = []
    for item in ranked:
        mut = item["mutation"]
        if not mut or mut in seen:
            continue
        seen.add(mut)
        values.append(item)
        if len(values) >= limit:
            break

    return values


def choose_pivot_values(trace_bundle: dict, limit: int = 3):
    mutation_output = trace_bundle.get("mutation_output", {}) or {}
    exploit_output = trace_bundle.get("exploit_output", {}) or {}
    candidate_inputs = trace_bundle.get("candidate_inputs", []) or []

    strong = best_confirmed_mutation_values(mutation_output, exploit_output, limit=limit)
    if strong:
        return strong

    seed_value = extract_seed_object_value(candidate_inputs)
    if seed_value:
        return [{
            "mutation": seed_value,
            "url": trace_bundle.get("url", ""),
            "rank": 1,
            "status_code": trace_bundle.get("current", {}).get("status_code"),
            "verdict": "SEED_VALUE"
        }]

    return []


def replace_numeric_or_placeholder_path(path: str, new_value: str):
    text = str(path or "").strip()
    if not text:
        return text

    segments = text.strip("/").split("/")
    replaced = False

    for i, seg in enumerate(segments):
        lower_seg = seg.lower()

        if seg == "{id}" or seg == ":id" or lower_seg == "nan":
            segments[i] = str(new_value)
            replaced = True
            break

    if not replaced:
        for i, seg in enumerate(segments):
            if seg.isdigit():
                segments[i] = str(new_value)
                replaced = True
                break

    if not replaced:
        return text

    return "/" + "/".join(segments)


def absolute_url_from_path(base_url: str, path: str):
    parsed = urlparse(base_url)
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        "",
        "",
        ""
    ))


def build_pivot_candidates(
    trace_bundle: dict,
    graph_context: dict | None = None,
    max_candidates: int = PIVOT_DEFAULT_LIMIT
):
    if graph_context is None:
        graph_context = {}

    attack_chain = trace_bundle.get("attack_chain", {}) or {}
    neighbors = attack_chain.get("neighbors", []) or []
    pivot_values = choose_pivot_values(trace_bundle, limit=3)
    base_url = trace_bundle.get("url", "")

    candidates = []
    seen = set()

    for pv in pivot_values:
        mutation_value = pv.get("mutation", "")
        for neighbor in neighbors:
            if not isinstance(neighbor, dict):
                continue

            parsed_target = parse_neighbor_target(neighbor.get("target", ""))
            neighbor_method = parsed_target["method"]
            neighbor_path = parsed_target["path"]

            rewritten_path = replace_numeric_or_placeholder_path(neighbor_path, mutation_value)
            if not rewritten_path:
                continue

            absolute_url = absolute_url_from_path(base_url, rewritten_path)

            key = (neighbor_method, rewritten_path, mutation_value)
            if key in seen:
                continue
            seen.add(key)

            candidates.append({
                "seed_trace_id": trace_bundle.get("trace_id"),
                "seed_path": trace_bundle.get("path"),
                "pivot_value": mutation_value,
                "neighbor_reason": neighbor.get("reason", ""),
                "neighbor_score": int(neighbor.get("score", 0) or 0),
                "neighbor_kind": neighbor.get("kind", ""),
                "method": neighbor_method,
                "path": rewritten_path,
                "url": absolute_url,
                "source_mutation_url": pv.get("url", ""),
                "source_mutation_verdict": pv.get("verdict", ""),
                "source_mutation_rank": pv.get("rank", 0)
            })

    candidates.sort(
        key=lambda item: enhanced_pivot_rank(item, trace_bundle, graph_context),
        reverse=True
    )
    return candidates[:max_candidates]

def sanitize_headers_for_pivot(headers: dict):
    clean = dict(headers or {})
    clean.pop("X-API-Key", None)
    clean.pop("Content-Length", None)
    clean.pop("content-length", None)
    return clean


def build_pivot_body(original_body: str, candidate: dict):
    """
    Keep original body for now.
    Later you can add JSON/body identifier rewriting.
    """
    return original_body or ""


def analyze_pivot_result(seed_current: dict, pivot_result: dict, candidate: dict):
    base = {
        "status_code": seed_current.get("status_code", 0),
        "length": seed_current.get("length", 0),
        "fingerprint": seed_current.get("fingerprint", ""),
        "fields": seed_current.get("fields", {}),
        "normalized_fields": seed_current.get("normalized_fields", {})
    }

    analysis = exploit_confirmation(
        base,
        pivot_result,
        "pivot_object",
        "",
        candidate.get("pivot_value", "")
    )

    method = candidate.get("method", "GET").upper()
    path = candidate.get("path", "")

    return {
        "method": method,
        "path": path,
        "url": candidate.get("url", ""),
        "status_code": pivot_result.get("status_code"),
        "length": pivot_result.get("length"),
        "fingerprint": pivot_result.get("fingerprint"),
        "body": pivot_result.get("body", ""),                     # NEW
        "fields": pivot_result.get("fields", {}),                 # NEW
        "normalized_fields": pivot_result.get("normalized_fields", {}),  # NEW
        "analysis": analysis,
        "neighbor_reason": candidate.get("neighbor_reason", ""),
        "neighbor_kind": candidate.get("neighbor_kind", ""),
        "pivot_value": candidate.get("pivot_value", ""),
        "preview_only": False
    }

def pivot_result_rank(item: dict):
    if item.get("error"):
        return -100

    analysis = item.get("analysis", {}) or {}
    verdict = str(analysis.get("verdict", ""))
    score = int(analysis.get("score", 0) or 0)
    flags = analysis.get("flags", {}) or {}

    rank = 0
    if verdict == "HIGH PROBABILITY IDOR":
        rank += 100
    elif verdict == "POSSIBLE AUTH/OBJECT ISSUE":
        rank += 60
    elif verdict == "AUTH BOUNDARY DIFFERENCE":
        rank += 15

    if flags.get("successful_cross_object_behavior"):
        rank += 30
    if flags.get("sensitive_disclosure_signal"):
        rank += 25
    if flags.get("auth_boundary_only"):
        rank -= 10

    rank += score
    rank += int(item.get("neighbor_score", 0) or 0)
    return rank


# ============================================
# ENHANCED PIVOT SCORING (A)
# ============================================

def get_attack_chain_stage_weight(stage: str) -> int:
    weights = {
        "object-access": 20,
        "identity-resource": 15,
        "action": 18,
        "discovery": 5,
        "general": 0
    }
    return weights.get(stage, 0)

def get_graph_risk_weight(normalized_path: str, graph_context: dict) -> int:
    if not graph_context:
        return 0
    high_risk_nodes = graph_context.get("high_risk", [])
    if normalized_path in high_risk_nodes:
        return 15
    return 0

def get_corroboration_weight(trace_bundle: dict, target_path: str) -> int:
    corroboration = trace_bundle.get("corroboration", {})
    if not corroboration.get("strong_finding_count", 0):
        return 0
    families = graph_object_families(trace_bundle.get("graph", {}))
    target_family = path_resource_family(target_path)
    if target_family and target_family in families:
        return 25
    return 0

def enhanced_pivot_rank(candidate: dict, trace_bundle: dict, graph_context: dict) -> int:
    rank = 0
    rank += int(candidate.get("neighbor_score", 0) or 0)
    rank += int(candidate.get("source_mutation_rank", 0) or 0)

    attack_chain = trace_bundle.get("attack_chain", {})
    stage = attack_chain.get("seed", {}).get("stage", "general")
    rank += get_attack_chain_stage_weight(stage)

    normalized_path = normalize_path_for_graph(candidate.get("path", ""))
    rank += get_graph_risk_weight(normalized_path, graph_context)

    rank += get_corroboration_weight(trace_bundle, candidate.get("path", ""))

    method = candidate.get("method", "GET").upper()
    if method in PIVOT_SAFE_METHODS:
        rank += 20
    elif method in PIVOT_ACTION_METHODS:
        rank += 5

    if is_business_path(candidate.get("path", "")):
        rank += 10

    return rank

def compute_confidence(analysis: dict, delta: dict, detection_hint: str = None) -> int:
    """Return a confidence score 0-100 based on evidence strength."""
    score = 0
    verdict = analysis.get("verdict", "")
    flags = analysis.get("flags", {})

    # Base from verdict
    if verdict == "HIGH PROBABILITY IDOR":
        score += 50
    elif verdict == "POSSIBLE AUTH/OBJECT ISSUE":
        score += 30
    elif verdict == "AUTH BOUNDARY DIFFERENCE":
        score += 10

    # Flags boost
    if flags.get("successful_cross_object_behavior"):
        score += 15
    if flags.get("sensitive_disclosure_signal"):
        score += 15
    if flags.get("ownership_signal"):
        score += 10

    # Delta
    if delta.get("status_changed"):
        score += 10
    if delta.get("length_diff", 0) > 500:
        score += 8
    elif delta.get("length_diff", 0) > 200:
        score += 4

    # Detection hints
    if detection_hint in ("admin_data_exposed", "sensitive_token_leak"):
        score += 20
    elif detection_hint == "error_leakage":
        score += 10
    elif detection_hint == "possible_access_control_issue":
        score += 15
    elif detection_hint == "significant_response_change":
        score += 8
    elif detection_hint == "possible_blind_injection":
        score += 5

    # Cap at 100
    return min(score, 100)

def build_graph_context(trace_bundle: dict) -> dict:
    attack_chain = trace_bundle.get("attack_chain", {})
    neighbors = attack_chain.get("neighbors", []) or []
    high_value = [n for n in neighbors if n.get("score", 0) > 70]
    return {
        "neighbor_count": len(neighbors),
        "high_value_neighbors": high_value,
        "high_risk": []   # you can populate from persistent graph later
    }

def execute_pivot_candidates(
    trace_bundle: dict,
    candidates: list,
    allow_action_pivots: bool = False,
    max_results: int = PIVOT_DEFAULT_LIMIT
):
    results = []
    seed_current = trace_bundle.get("current", {}) or {}
    headers = sanitize_headers_for_pivot(trace_bundle.get("request_headers", {}) or {})
    original_body = trace_bundle.get("request_body", "") or ""
    program = trace_bundle.get("program", "local-lab")

    baseline_status = seed_current.get("status_code", 0)
    baseline_length = seed_current.get("length", 0)

    for candidate in candidates[:max_results]:
        method = candidate.get("method", "GET").upper()

        if method in PIVOT_ACTION_METHODS and not allow_action_pivots:
            results.append({
                "method": method,
                "path": candidate.get("path", ""),
                "url": candidate.get("url", ""),
                "pivot_value": candidate.get("pivot_value", ""),
                "neighbor_reason": candidate.get("neighbor_reason", ""),
                "neighbor_kind": candidate.get("neighbor_kind", ""),
                "neighbor_score": candidate.get("neighbor_score", 0),
                "preview_only": True,
                "preview_reason": "action pivot blocked by default; set allow_action_pivots=true to execute"
            })
            continue

        try:
            pivot_body = build_pivot_body(original_body, candidate)
            replay = perform_request(
                method=method,
                url=candidate.get("url", ""),
                headers=headers,
                body=pivot_body,
                strip_auth=False,
                timeout=AUTO_MUTATION_TIMEOUT,
                program=program
            )

            status = replay.get("status_code", 0)
            length = replay.get("length", 0)
            delta = {
                "status_changed": status != baseline_status,
                "length_diff": abs(length - baseline_length)
            }
            response_preview = replay.get("body", "")[:2000]

            analyzed = analyze_pivot_result(seed_current, replay, candidate)
            analyzed.update({
                "delta": delta,
                "response_preview": response_preview,
                "error_class": None,
                "detection_hint": None
            })

            lower_preview = response_preview.lower()
            if delta["status_changed"] and 200 <= status < 300:
                analyzed["detection_hint"] = "possible_access_control_issue"
            elif replay.get("error") == "timeout":
                analyzed["detection_hint"] = "possible_blind_injection"
            elif delta["length_diff"] > 500:
                analyzed["detection_hint"] = "significant_response_change"
            elif "error" in lower_preview or "exception" in lower_preview:
                analyzed["detection_hint"] = "error_leakage"
            elif "admin" in lower_preview:
                analyzed["detection_hint"] = "admin_data_exposed"
            elif "token" in lower_preview or "jwt" in lower_preview:
                analyzed["detection_hint"] = "sensitive_token_leak"
            elif status == 200 and ("error" in lower_preview or "exception" in lower_preview):
                analyzed["detection_hint"] = "hidden_error_message"

            analyzed["confidence"] = compute_confidence(
                analyzed.get("analysis", {}),
                delta,
                analyzed.get("detection_hint")
            )
            results.append(analyzed)

        except Exception as e:
            error_str = str(e).lower()
            if "timeout" in error_str:
                detection_hint = "possible_blind_injection"
                error_class = "timeout"
            elif "connection" in error_str:
                detection_hint = "possible_filtering"
                error_class = "connection_error"
            elif "ssl" in error_str:
                detection_hint = "ssl_misconfiguration"
                error_class = "ssl_error"
            else:
                detection_hint = None
                error_class = "unknown"
            results.append({
                "method": method,
                "path": candidate.get("path", ""),
                "url": candidate.get("url", ""),
                "pivot_value": candidate.get("pivot_value", ""),
                "neighbor_reason": candidate.get("neighbor_reason", ""),
                "neighbor_kind": candidate.get("neighbor_kind", ""),
                "neighbor_score": candidate.get("neighbor_score", 0),
                "error": str(e),
                "error_class": error_class,
                "detection_hint": detection_hint
            })

    results.sort(key=pivot_result_rank, reverse=True)

    meaningful = [
        r for r in results
        if not r.get("preview_only")
        and not r.get("error")
        and (
            (r.get("analysis", {}).get("score", 0) >= 5)
            or (r.get("analysis", {}).get("verdict") == "HIGH PROBABILITY IDOR")
            or r.get("detection_hint") in ("possible_access_control_issue", "significant_response_change")
            or r.get("confidence", 0) >= 40
        )
    ]

    return {
        "performed": True,
        "candidate_count": len(candidates),
        "executed_count": len([r for r in results if not r.get("preview_only")]),
        "preview_only_count": len([r for r in results if r.get("preview_only")]),
        "meaningful_count": len(meaningful),
        "results": results
    }

def format_pivot_for_response(pivot_result: dict) -> dict:
    """Make pivot execution output JSON‑safe and succinct."""
    results = []
    for r in pivot_result.get("results", []):
        entry = {
            "method": r.get("method"),
            "url": r.get("url"),
            "status_code": r.get("status_code"),
            "verdict": r.get("analysis", {}).get("verdict") if not r.get("error") else None,
            "score": r.get("analysis", {}).get("score") if not r.get("error") else None,
        }
        if r.get("error"):
            entry["error"] = r.get("error")
        if r.get("preview_only"):
            entry["preview_only"] = True
            entry["preview_reason"] = r.get("preview_reason")
        results.append(entry)
    return {
        "performed": pivot_result.get("performed"),
        "candidate_count": pivot_result.get("candidate_count"),
        "executed_count": pivot_result.get("executed_count"),
        "meaningful_count": pivot_result.get("meaningful_count"),
        "results": results
    }

def save_attack_path(trace_id: str, program: str, chain: list):
    conn = get_db()
    conn.execute("""
        INSERT INTO attack_paths (trace_id, program, chain_json, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        trace_id,
        program,
        json.dumps(make_json_safe(chain)),
        utc_now_iso()
    ))
    conn.commit()
    conn.close()
def send_exploit_webhook(trace_id: str, findings: dict):
    if not EXPLOIT_WEBHOOK_URL:
        return
    try:
        payload = {
            "trace_id": trace_id,
            "timestamp": utc_now_iso(),
            "findings": findings
        }
        requests.post(EXPLOIT_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        logger.warning(f"Webhook failed for trace {trace_id}: {e}")

# ============================================
# ROUTES
# ============================================

@app.route("/health")
def health():
    return jsonify({
        "ok": True,
        "service": "gateway",
        "db_path": DB_PATH,
        "api_key_configured": bool(API_KEY),
        "allowed_target_hosts": ALLOWED_TARGET_HOSTS,
        "allow_private_hosts": ALLOW_PRIVATE_HOSTS,
        "allow_localhost_targets": ALLOW_LOCALHOST_TARGETS,
        "program_scope_policies_configured": bool(load_program_scope_policies())
    })

@app.route("/ingest", methods=["POST"])
@require_api_key
def ingest():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"ok": False, "error": "Invalid or empty JSON"}), 400
    trace_id = new_trace_id()
    ingest_start_ms = now_ms()

    parse_ms_start = now_ms()
    parsed = parse_ingest_request(data)
    parse_request_ms = elapsed_ms(parse_ms_start)

    program = parsed["program"]
    method = parsed["method"]
    url = parsed["url"]
    headers = parsed["headers"]
    body = parsed["body"]
    response_text = parsed["response_text"]
    status_code = parsed["status_code"]
    payload_multi_auth_profiles = parsed["payload_multi_auth_profiles"]
    path = parsed["path"]
    query = parsed["query"]
    auth_state = parsed["auth_state"]

    print(f"[+] Incoming request processed for path: {path}")

    build_ms_start = now_ms()
    current = build_current_response_state(response_text, status_code)
    all_params = build_candidate_inputs(url, headers, body)
    build_state_ms = elapsed_ms(build_ms_start)

    log_event(
        "info",
        trace_id,
        "ingest_received",
        program=program,
        method=method,
        url=url,
        path=path,
        auth_state=auth_state
    )

    history = load_history(path, method, program)

    replay_results = run_replay_stages(
        trace_id=trace_id,
        path=path,
        url=url,
        method=method,
        headers=headers,
        body=body,
        current=current,
        all_params=all_params,
        payload_multi_auth_profiles=payload_multi_auth_profiles,
        program=program
    )

    replay = replay_results["replay"]
    mutation_replay = replay_results["mutation_replay"]
    multi_auth_result = replay_results["multi_auth_result"]
    replay_timings = replay_results.get("timings", {})

    analysis = run_analysis_stage(
        trace_id=trace_id,
        program=program,
        path=path,
        method=method,
        url=url,
        headers=headers,
        body=body,
        current=current,
        all_params=all_params,
        history=history,
        replay=replay,
        mutation_replay=mutation_replay,
        multi_auth_result=multi_auth_result,
        payload_multi_auth_profiles=payload_multi_auth_profiles
    )

    analysis_check = validate_analysis_bundle(analysis)
    if not analysis_check["ok"]:
        log_event(
            "error",
            trace_id,
            "analysis_bundle_incomplete",
            missing=analysis_check["missing"],
            path=path
        )

    diff = analysis["diff"]
    graph = analysis["graph"]
    related_history = analysis["related_history"]
    fuzzing = analysis["fuzzing"]
    attack_chain = analysis["attack_chain"]
    corroboration = analysis["corroboration"]

    exploit = analysis["exploit"]
    exploit_output = analysis["exploit_output"]
    mutation_output = analysis["mutation_output"]
    multi_auth_output = analysis["multi_auth_output"]

    signals = analysis["signals"]
    sorted_signals = analysis["sorted_signals"]

    risk_score = analysis["risk_score"]
    reasons = analysis["reasons"]

    suggestions = analysis["suggestions"]
    sorted_suggestions = analysis["sorted_suggestions"]

    narratives = analysis["narratives"]
    sorted_narratives = analysis["sorted_narratives"]
    top_narrative = analysis["top_narrative"]

    priority_findings = analysis["priority_findings"]
    evidence_summary = analysis["evidence_summary"]
    report_findings = analysis["report_findings"]

    analysis_timings = analysis.get("timings", {})

    save_observation(
        program=program,
        method=method,
        path=path,
        query=query,
        status_code=status_code,
        response_length=len(response_text),
        auth_state=auth_state,
        fingerprint_value=current["fingerprint"]
    )

    # ========== PHASE 3 & 5: BUILD INTELLIGENCE & HYPOTHESES ==========
    # First, build the full trace bundle (needed for decision engine and hypotheses)
    trace_bundle = {
        "trace_id": trace_id,
        "program": program,
        "url": url,
        "method": method,
        "path": path,
        "request_headers": headers,
        "request_body": body,
        "current": current,
        "candidate_inputs": all_params,
        "mutation_replay": mutation_replay,
        "multi_auth_result": multi_auth_result,
        "payload_multi_auth_profiles": payload_multi_auth_profiles
    }

    intel_bundle = {
        "request_headers": headers,
        "response_text": response_text,
        "path": path,
        "method": method,
        "status_code": status_code
    }
    intel = build_endpoint_intelligence(intel_bundle)
    intel_score = score_endpoint_intelligence(intel)
    auth_state = summarize_auth_state_from_headers(headers)
    next_actions = choose_next_actions(trace_bundle, intel, intel_score)

    # Phase 5: Hypotheses and smart payloads
    hypotheses = rank_hypotheses(trace_bundle, intel, mutation_replay, multi_auth_result)
    smart_payloads = []
    if hypotheses:
        smart_payloads = generate_smart_payloads(intel, hypotheses[0])

    # Save intelligence to DB
    conn = get_db()
    conn.execute(
        "INSERT INTO endpoint_intelligence (trace_id, normalized_path, family, score, created_at) VALUES (?,?,?,?,?)",
        (trace_id, intel["normalized_path"], intel["family"], intel_score, utc_now_iso())
    )
    conn.execute(
        "INSERT INTO auth_state_memory (trace_id, normalized_path, auth_state, status_code, created_at) VALUES (?,?,?,?,?)",
        (trace_id, intel["normalized_path"], auth_state, status_code, utc_now_iso())
    )
    conn.commit()
    conn.close()

    # We will add the fields to the final response later – do NOT set response here

    save_trace_run(
        trace_id=trace_id,
        program=program,
        method=method,
        path=path,
        url=url,
        request_headers=headers,
        request_body=body,
        current=current,
        candidate_inputs=all_params,
        attack_chain=attack_chain,
        mutation_output=mutation_output,
        multi_auth_output=multi_auth_output,
        corroboration=corroboration,
        exploit_output=exploit_output
    )

    # Phase 4: Run decision engine (high-priority actions)
    decision_results = run_decision_engine(trace_id, trace_bundle, intel, intel_score, next_actions)

# ------------------------------------------------------------
# AUTO PIVOT (non‑recursive, safe by default)
# ------------------------------------------------------------
    auto_pivot_result = None
    if attack_chain and exploit_output.get("confirmed", 0) > 0:
        try:
            trace_bundle = {
                "trace_id": trace_id,
                "path": path,
                "url": url,
                "program": program,
                "current": current,
                "request_headers": headers,
                "request_body": body,
                "candidate_inputs": all_params,
                "attack_chain": attack_chain,
                "mutation_output": mutation_output,
                "exploit_output": exploit_output,
                "corroboration": corroboration,
                "graph": graph
            }

            candidates = build_pivot_candidates(trace_bundle, graph_context=build_graph_context(trace_bundle), max_candidates=5)
            if candidates:
                pivot_exec = execute_pivot_candidates(
                    trace_bundle, candidates,
                    allow_action_pivots=False,
                    max_results=5
                )
                for res in pivot_exec.get("results", []):
                    if not res.get("preview_only"):   # only save executed pivots
                        save_pivot_attempt(trace_id, path, res)

                auto_pivot_result = format_pivot_for_response(pivot_exec)
        except Exception as e:
            logger.warning(f"Auto pivot failed for trace {trace_id}: {e}")

    persist_endpoint_graph_memory(
        program=program,
        method=method,
        path=path,
        auth_state=auth_state,
        graph=graph
    )

    total_ms = elapsed_ms(ingest_start_ms)

    log_event(
        "info",
        trace_id,
        "ingest_completed",
        path=path,
        risk_score=risk_score,
        signal_count=len(signals),
        suggestion_count=len(suggestions),
        attack_chain_stage=attack_chain.get("seed", {}).get("stage", "general"),
        total_ms=total_ms,
        parse_request_ms=parse_request_ms,
        build_state_ms=build_state_ms,
        replay_timings=replay_timings,
        analysis_timings=analysis_timings
    )

    response = {
        "ok": True,
        "trace_id": trace_id,
        "path": path,
        "query": query,
        "risk_score": risk_score,
        "priority_findings": priority_findings,
        "top_narrative": top_narrative,
        "exploit_narratives": sorted_narratives,
        "top_report_finding": report_findings[0] if report_findings else None,
        "report_ready_findings": report_findings,
        "reasons": reasons,
        "evidence_summary": evidence_summary,
        "auto_replay": replay,
        "auto_mutation_replay": mutation_output,
        "auto_multi_auth_replay": multi_auth_output,
        "true_cross_user_corroboration": corroboration,
        "auto_exploit_replay": exploit_output,
        "detection_signals": sorted_signals,
        "diff_engine": diff,
        "fuzzing_hints": fuzzing,
        "exploit_suggestions": sorted_suggestions,
        "endpoint_intelligence": intel,
        "endpoint_score": intel_score,
        "next_actions": next_actions,
        "auth_state": auth_state,
        "decision_engine": decision_results,
        "hypotheses": hypotheses,
        "smart_payloads": smart_payloads,
        "endpoint_graph": graph,
        "endpoint_graph_related_history": related_history,
        "endpoint_graph_hints": endpoint_graph_hints(graph),
        "endpoint_graph_persistent_node_memory": graph.get("persistent_node_memory"),
        "endpoint_graph_persistent_edge_memory": graph.get("persistent_edge_memory", []),
        "endpoint_graph_persistent_auth_memory": graph.get("persistent_auth_memory", []),
        "attack_chain": attack_chain,
        "attack_chain_hints": attack_chain_hints(attack_chain),
        "candidate_inputs": all_params,
        "leaderboard": leaderboard(program),
        "corroboration_summary": {
            "performed": corroboration.get("performed", False),
            "meaningful_count": corroboration.get("meaningful_count", 0),
            "strong_finding_count": corroboration.get("strong_finding_count", 0),
            "auth_boundary_count": corroboration.get("auth_boundary_count", 0),
            "shared_or_public_count": corroboration.get("shared_or_public_count", 0),
            "profiles_used": corroboration.get("profiles_used", [])
        },
        "auto_pivot": auto_pivot_result,
        "analysis_bundle_check": analysis_check,
        "timings": {
            "total_ms": elapsed_ms(ingest_start_ms),
            "parse_request_ms": parse_request_ms,
            "build_state_ms": build_state_ms,
            "replay": replay_timings,
            "analysis": analysis_timings
        }
    }

    # Webhook if confirmed exploit (moved outside the response dict)
    if exploit_output.get("confirmed", 0) > 0 or any(s.get("type") in ("confirmed-exploit", "cross-user-corroborated-object-access") for s in sorted_signals):
        webhook_findings = {
            "confirmed_exploit": exploit_output.get("confirmed", 0) > 0,
            "cross_user_corroborated": any(s.get("type") == "cross-user-corroborated-object-access" for s in sorted_signals),
            "risk_score": risk_score,
            "top_narrative": top_narrative.get("summary") if top_narrative else None
        }
        send_exploit_webhook(trace_id, webhook_findings)

    return jsonify(make_json_safe(response))

@app.route("/chain/<trace_id>/pivot", methods=["POST"])
@require_api_key
def pivot_from_trace(trace_id):
    data = request.get_json(silent=True) or {}

    allow_action_pivots = bool(data.get("allow_action_pivots", False))
    max_candidates = int(data.get("max_candidates", PIVOT_DEFAULT_LIMIT) or PIVOT_DEFAULT_LIMIT)
    max_results = int(data.get("max_results", PIVOT_DEFAULT_LIMIT) or PIVOT_DEFAULT_LIMIT)

    trace_bundle = load_trace_run(trace_id)
    if not trace_bundle:
        return jsonify({
            "ok": False,
            "error": "trace_not_found",
            "trace_id": trace_id
        }), 404

    candidates = build_pivot_candidates(trace_bundle, graph_context = build_graph_context(trace_bundle), max_candidates=max_candidates)

    if not candidates:
        return jsonify({
            "ok": False,
            "error": "no_pivot_candidates",
            "trace_id": trace_id
        }), 400

    pivot_result = execute_pivot_candidates(
        trace_bundle=trace_bundle,
        candidates=candidates,
        allow_action_pivots=allow_action_pivots,
        max_results=max_results
    )

    return jsonify(make_json_safe({
        "ok": True,
        "trace_id": trace_id,
        "seed_path": trace_bundle.get("path"),
        "seed_url": trace_bundle.get("url"),
        "allow_action_pivots": allow_action_pivots,
        "pivot_candidates": candidates,
        "pivot_execution": pivot_result
    }))

@app.route("/chain/<trace_id>/pivot/recursive", methods=["POST"])
@require_api_key
def recursive_pivot_from_trace(trace_id):
    data = request.get_json(silent=True) or {}
    max_depth = int(data.get("max_depth", 3))
    allow_action_pivots = bool(data.get("allow_action_pivots", False))

    trace_bundle = load_trace_run(trace_id)
    if not trace_bundle:
        return jsonify({"ok": False, "error": "trace_not_found"}), 404

    chain = []
    current_bundle = trace_bundle
    current_depth = 0
    all_pivots = []

    while current_depth < max_depth:
        # Build pivot candidates from current bundle
        candidates = build_pivot_candidates(
            current_bundle,
            graph_context=build_graph_context(current_bundle),  # ✅ correct
            max_candidates=5
        )
        if not candidates:
            break

        pivot_exec = execute_pivot_candidates(
            current_bundle, candidates,
            allow_action_pivots=allow_action_pivots,
            max_results=5
        )

        # Find meaningful pivots (score >=5 or HIGH PROBABILITY IDOR)
        meaningful = []
        for r in pivot_exec.get("results", []):
            if r.get("error"):
                continue
            analysis = r.get("analysis", {})
            score = analysis.get("score", 0)
            verdict = analysis.get("verdict", "")
            if score >= 5 or verdict == "HIGH PROBABILITY IDOR":
                meaningful.append(r)

        if not meaningful:
            break

        # Save all pivot attempts for this step
        for r in pivot_exec.get("results", []):
            save_pivot_attempt(trace_id, current_bundle.get("path"), r)
            all_pivots.append(r)

        # Use the first meaningful pivot as next seed
        best = meaningful[0]

        # Rebuild current state from the FULL pivot result
        new_current = {
            "status_code": best.get("status_code"),
            "length": best.get("length"),
            "fingerprint": best.get("fingerprint"),
            "fields": best.get("fields", {}),
            "normalized_fields": best.get("normalized_fields", {}),
            "response_text": best.get("body", "")
        }

        # Re-extract candidate inputs from the pivot URL
        new_url = best.get("url", "")
        new_headers = current_bundle.get("request_headers", {})
        new_body = current_bundle.get("request_body", "")  # keep original body for the next request
        new_params = build_candidate_inputs(new_url, new_headers, new_body)

        # Build a new attack chain for the next hop (optional but improves context)
        new_graph = endpoint_intelligence_graph(
            path=best.get("path", ""),
            method=best.get("method", "GET"),
            candidate_inputs=new_params,
            history=[],
            signals=[]
        )
        new_graph = enrich_graph_with_persistent_memory(trace_bundle.get("program", "local-lab"), new_graph)
        new_related_history = graph_history_similarity(best.get("path", ""), best.get("method", "GET"), trace_bundle.get("program", "local-lab"))
        new_attack_chain = build_attack_chain(
            seed=build_attack_chain_seed(best.get("path", ""), best.get("method", "GET"), new_graph, [], []),
            graph=new_graph,
            related_history=new_related_history
        )

        # Prepare next bundle
        current_bundle = {
            "trace_id": trace_id,
            "path": best.get("path", ""),
            "url": new_url,
            "current": new_current,
            "request_headers": new_headers,
            "request_body": new_body,
            "candidate_inputs": new_params,
            "attack_chain": new_attack_chain,
            "mutation_output": {},
            "exploit_output": {"confirmed": 1}
        }

        chain.append({
            "depth": current_depth,
            "pivot": {
                "method": best.get("method"),
                "url": best.get("url"),
                "status_code": best.get("status_code"),
                "verdict": best.get("analysis", {}).get("verdict")
            }
        })
        current_depth += 1

    return jsonify(make_json_safe({
        "ok": True,
        "trace_id": trace_id,
        "max_depth": max_depth,
        "chain_length": len(chain),
        "chain": chain,
        "all_pivots": all_pivots
    }))

@app.route("/chain/<trace_id>/deep_pivot", methods=["POST"])
@require_api_key
def deep_pivot_from_trace(trace_id):
    """
    Adaptive recursive pivot: explores attack path until no new high-confidence pivots,
    returns full chain, avoids cycles.
    """
    data = request.get_json(silent=True) or {}
    max_depth = int(data.get("max_depth", 5))
    allow_action_pivots = bool(data.get("allow_action_pivots", False))
    min_score_threshold = int(data.get("min_score_threshold", 20))

    trace_bundle = load_trace_run(trace_id)
    if not trace_bundle:
        return jsonify({"ok": False, "error": "trace_not_found"}), 404

    graph_context = build_graph_context(trace_bundle)

    visited = set()
    chain = []
    current_bundle = trace_bundle
    current_depth = 0

    while current_depth < max_depth:
        # Cycle prevention
        current_node_key = (
            current_bundle.get("method", "GET"),
            normalize_path_for_graph(current_bundle.get("path", "")),
            current_bundle.get("pivot_value", "")
        )
        if current_node_key in visited:
            break
        visited.add(current_node_key)

        attack_chain = current_bundle.get("attack_chain", {})
        graph = current_bundle.get("graph", {})

        candidates = build_pivot_candidates(current_bundle, graph_context, max_candidates=5)
        if not candidates:
            break

        pivot_exec = execute_pivot_candidates(
            current_bundle, candidates,
            allow_action_pivots=allow_action_pivots,
            max_results=5
        )

        # Find meaningful pivots (score >= threshold or HIGH PROBABILITY IDOR)
        meaningful = []
        for r in pivot_exec.get("results", []):
            if r.get("error"):
                continue
            analysis = r.get("analysis", {})
            score = analysis.get("score", 0)
            verdict = analysis.get("verdict", "")
            if score >= min_score_threshold or verdict == "HIGH PROBABILITY IDOR":
                meaningful.append(r)

        if not meaningful:
            break

        best = meaningful[0]

        # Check if any result is a confirmed exploit (HIGH PROBABILITY IDOR + success status)
        confirmed_any = any(
            r.get("analysis", {}).get("verdict") == "HIGH PROBABILITY IDOR"
            and r.get("status_code", 0) in (200, 201, 202, 204)
            for r in pivot_exec.get("results", [])
        )

        if confirmed_any:
            chain.append({
                "depth": current_depth,
                "method": best.get("method"),
                "url": best.get("url"),
                "status_code": best.get("status_code"),
                "verdict": best.get("analysis", {}).get("verdict"),
                "score": best.get("analysis", {}).get("score", 0),
                "pivot_value": best.get("pivot_value"),
                "neighbor_reason": best.get("neighbor_reason"),
                "confirmed_exploit": True
            })
            break

        # Prepare next bundle for deeper pivot
        new_current = {
            "status_code": best.get("status_code"),
            "length": best.get("length"),
            "fingerprint": best.get("fingerprint"),
            "fields": best.get("fields", {}),
            "normalized_fields": best.get("normalized_fields", {}),
            "response_text": best.get("body", "")
        }
        new_url = best.get("url", "")
        new_headers = current_bundle.get("request_headers", {})
        new_body = current_bundle.get("request_body", "")
        new_params = build_candidate_inputs(new_url, new_headers, new_body)

        new_graph = endpoint_intelligence_graph(
            path=best.get("path", ""),
            method=best.get("method", "GET"),
            candidate_inputs=new_params,
            history=[],
            signals=[]
        )
        new_graph = enrich_graph_with_persistent_memory(trace_bundle.get("program", "local-lab"), new_graph)
        new_attack_chain = build_attack_chain(
            seed=build_attack_chain_seed(best.get("path", ""), best.get("method", "GET"), new_graph, [], []),
            graph=new_graph,
            related_history=[]
        )

        current_bundle = {
            "trace_id": trace_id,
            "path": best.get("path", ""),
            "url": new_url,
            "current": new_current,
            "request_headers": new_headers,
            "request_body": new_body,
            "candidate_inputs": new_params,
            "attack_chain": new_attack_chain,
            "graph": new_graph,
            "program": trace_bundle.get("program", "local-lab")
        }

        chain.append({
            "depth": current_depth,
            "method": best.get("method"),
            "url": new_url,
            "status_code": best.get("status_code"),
            "verdict": best.get("analysis", {}).get("verdict"),
            "score": best.get("analysis", {}).get("score", 0),
            "pivot_value": best.get("pivot_value"),
            "neighbor_reason": best.get("neighbor_reason")
        })

        current_depth += 1

    if chain:
        save_attack_path(trace_id, trace_bundle.get("program", "local-lab"), chain)

    return jsonify(make_json_safe({
        "ok": True,
        "trace_id": trace_id,
        "max_depth": max_depth,
        "chain_length": len(chain),
        "chain": chain,
        "visited_count": len(visited)
    }))

@app.route("/attack_paths/<trace_id>", methods=["GET"])
@require_api_key
def get_attack_paths(trace_id):
    conn = get_db()
    rows = conn.execute("""
        SELECT id, chain_json, created_at
        FROM attack_paths
        WHERE trace_id = ?
        ORDER BY created_at DESC
    """, (trace_id,)).fetchall()
    conn.close()
    paths = []
    for row in rows:
        paths.append({
            "id": row["id"],
            "chain": safe_json_loads(row["chain_json"]),
            "created_at": row["created_at"]
        })
    return jsonify({"ok": True, "trace_id": trace_id, "paths": paths})
# ============================================
# RUN
# ============================================

# ============================================
# TRACE MANAGEMENT ENDPOINTS
# ============================================

@app.route("/traces", methods=["GET"])
@require_api_key
def list_traces():
    """List recent traces with filtering and pagination."""
    limit = request.args.get("limit", default=50, type=int)
    offset = request.args.get("offset", default=0, type=int)
    program = request.args.get("program", default=None, type=str)
    from_date = request.args.get("from_date", default=None, type=str)
    to_date = request.args.get("to_date", default=None, type=str)
    min_risk_score = request.args.get("min_risk_score", default=None, type=int)

    conn = get_db()
    
    query = """
        SELECT trace_id, created_at, program, method, path, url,
               (SELECT COUNT(*) FROM attack_paths WHERE attack_paths.trace_id = trace_runs.trace_id) as attack_path_count
        FROM trace_runs
        WHERE 1=1
    """
    params = []
    
    if program:
        query += " AND program = ?"
        params.append(program)
    if from_date:
        query += " AND created_at >= ?"
        params.append(from_date)
    if to_date:
        query += " AND created_at <= ?"
        params.append(to_date)
    if min_risk_score is not None:
        query += """ AND trace_id IN (
            SELECT DISTINCT trace_id FROM endpoint_intelligence WHERE score >= ?
        )"""
        params.append(min_risk_score)
    
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    rows = conn.execute(query, params).fetchall()
    
    count_query = """
        SELECT COUNT(*) as total FROM trace_runs WHERE 1=1
    """
    count_params = []
    if program:
        count_query += " AND program = ?"
        count_params.append(program)
    if from_date:
        count_query += " AND created_at >= ?"
        count_params.append(from_date)
    if to_date:
        count_query += " AND created_at <= ?"
        count_params.append(to_date)
    if min_risk_score is not None:
        count_query += """ AND trace_id IN (
            SELECT DISTINCT trace_id FROM endpoint_intelligence WHERE score >= ?
        )"""
        count_params.append(min_risk_score)
    
    total = conn.execute(count_query, count_params).fetchone()["total"]
    conn.close()
    
    traces = []
    for row in rows:
        traces.append({
            "trace_id": row["trace_id"],
            "created_at": row["created_at"],
            "program": row["program"],
            "method": row["method"],
            "path": row["path"],
            "url": row["url"],
            "attack_path_count": row["attack_path_count"]
        })
    
    return jsonify({
        "ok": True,
        "program": program,
        "limit": limit,
        "offset": offset,
        "total": total,
        "traces": traces
    })

@app.route("/trace/<trace_id>", methods=["GET"])
@require_api_key
def get_trace(trace_id):
    """Retrieve full trace data by ID."""
    trace = load_trace_run(trace_id)
    if not trace:
        return jsonify({"ok": False, "error": "trace_not_found"}), 404
    
    # Also fetch pivot attempts for this trace
    conn = get_db()
    pivot_rows = conn.execute("""
        SELECT id, seed_path, pivot_target, pivot_value, method, url,
               status_code, length, fingerprint, verdict, score, error, created_at
        FROM pivot_attempts
        WHERE trace_id = ?
        ORDER BY created_at DESC
    """, (trace_id,)).fetchall()
    conn.close()
    
    pivot_attempts = []
    for row in pivot_rows:
        pivot_attempts.append({
            "id": row["id"],
            "seed_path": row["seed_path"],
            "pivot_target": row["pivot_target"],
            "pivot_value": row["pivot_value"],
            "method": row["method"],
            "url": row["url"],
            "status_code": row["status_code"],
            "length": row["length"],
            "fingerprint": row["fingerprint"],
            "verdict": row["verdict"],
            "score": row["score"],
            "error": row["error"],
            "created_at": row["created_at"]
        })
    
    trace["pivot_attempts"] = pivot_attempts
    return jsonify({"ok": True, "trace": make_json_safe(trace)})

@app.route("/trace/<trace_id>/report", methods=["GET"])
@require_api_key
def export_trace_report(trace_id):
    """Export findings for a trace as JSON or Markdown."""
    fmt = request.args.get("format", "json").lower()
    trace = load_trace_run(trace_id)
    if not trace:
        return jsonify({"ok": False, "error": "trace_not_found"}), 404
    
    # Build report object from stored data
    report = {
        "trace_id": trace_id,
        "created_at": trace.get("created_at"),
        "program": trace.get("program"),
        "method": trace.get("method"),
        "path": trace.get("path"),
        "url": trace.get("url"),
        "attack_chain_stage": trace.get("attack_chain", {}).get("seed", {}).get("stage"),
        "confirmed_exploit": trace.get("exploit_output", {}).get("confirmed", 0) > 0,
        "stable_exploit": trace.get("exploit_output", {}).get("stable_only", 0) > 0,
        "multi_auth_corroborated_difference": trace.get("multi_auth_output", {}).get("corroborated_difference_count", 0),
        "priority_findings": [],   # you could compute from signals if you stored them
        "report_findings": []
    }
    
    if fmt == "markdown":
        md = f"""# Hex Workbench Report: {trace_id}

**Created:** {report['created_at']}
**Program:** {report['program']}
**Method:** {report['method']}
**Path:** {report['path']}
**URL:** {report['url']}

## Attack Chain Stage
{report['attack_chain_stage'] or 'N/A'}

## Exploit Status
- Confirmed Exploit: {report['confirmed_exploit']}
- Stable Exploit Behavior: {report['stable_exploit']}
- Multi‑Auth Corroborated Differences: {report['multi_auth_corroborated_difference']}

## Raw Data
See attached JSON for full details.
"""
        return Response(md, mimetype="text/markdown")
    
    return jsonify({"ok": True, "report": make_json_safe(report)})

@app.route("/trace/<trace_id>", methods=["DELETE"])
@require_api_key
def delete_trace(trace_id):
    """Delete a trace and all related data (observations, pivots, attack paths)."""
    conn = get_db()
    
    # Delete from trace_runs
    conn.execute("DELETE FROM trace_runs WHERE trace_id = ?", (trace_id,))
    # Delete pivot attempts
    conn.execute("DELETE FROM pivot_attempts WHERE trace_id = ?", (trace_id,))
    # Delete attack paths
    conn.execute("DELETE FROM attack_paths WHERE trace_id = ?", (trace_id,))
    # Note: observations, graph nodes/edges are kept because they may be shared across traces
    
    conn.commit()
    conn.close()
    
    return jsonify({"ok": True, "message": f"Trace {trace_id} deleted"})


@app.route("/cleanup", methods=["POST"])
@require_api_key
def cleanup_old_traces():
    """Delete traces older than a given number of days (default 30)."""
    data = request.get_json(silent=True) or {}
    days = int(data.get("days", 30))
    
    cutoff = datetime.now(timezone.utc).isoformat()
    # We'll parse created_at as ISO and compare; SQLite can compare strings if format is consistent
    conn = get_db()
    
    # Find old trace_ids
    rows = conn.execute("""
        SELECT trace_id FROM trace_runs
        WHERE julianday('now') - julianday(created_at) > ?
    """, (days,)).fetchall()
    
    old_ids = [row["trace_id"] for row in rows]
    
    for tid in old_ids:
        conn.execute("DELETE FROM trace_runs WHERE trace_id = ?", (tid,))
        conn.execute("DELETE FROM pivot_attempts WHERE trace_id = ?", (tid,))
        conn.execute("DELETE FROM attack_paths WHERE trace_id = ?", (tid,))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        "ok": True,
        "deleted_count": len(old_ids),
        "deleted_traces": old_ids[:20]  # limit preview
    })


# ============================================
# SIMPLE HTML DASHBOARD (optional)
# ============================================

@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Enhanced HTML dashboard with risk scores and search."""
    conn = get_db()
    
    # Get search query
    search = request.args.get("search", "")
    
    # Recent observations
    obs_rows = conn.execute("""
        SELECT program, method, path, status_code, auth_state, fingerprint, created_at
        FROM observations
        ORDER BY created_at DESC
        LIMIT 50
    """).fetchall()
    
    # Recent traces with risk scores (joined with endpoint_intelligence)
    trace_query = """
        SELECT t.trace_id, t.created_at, t.program, t.method, t.path, t.url,
               MAX(e.score) as max_risk_score
        FROM trace_runs t
        LEFT JOIN endpoint_intelligence e ON t.trace_id = e.trace_id
    """
    if search:
        trace_query += " WHERE t.path LIKE ? OR t.trace_id LIKE ?"
        search_param = f"%{search}%"
        trace_rows = conn.execute(trace_query + " GROUP BY t.trace_id ORDER BY t.created_at DESC LIMIT 20", (search_param, search_param)).fetchall()
    else:
        trace_rows = conn.execute(trace_query + " GROUP BY t.trace_id ORDER BY t.created_at DESC LIMIT 20").fetchall()
    
    # High-risk endpoints
    intel_rows = conn.execute("""
        SELECT normalized_path, family, score, created_at
        FROM endpoint_intelligence
        WHERE score > 70
        ORDER BY score DESC
        LIMIT 30
    """).fetchall()
    
    conn.close()
    
    # Build HTML safely – escape braces by doubling them
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>Hex Workbench Dashboard</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .critical {{ background-color: #ffcccc; }}
        .high {{ background-color: #ffe5cc; }}
        .medium {{ background-color: #ffffcc; }}
        .low {{ background-color: #e6f7ff; }}
        .search-box {{ margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>Hex Workbench Dashboard</h1>
    
    <div class="search-box">
        <form method="get">
            <input type="text" name="search" placeholder="Search by path or trace ID" value="{}">
            <button type="submit">Search</button>
        </form>
    </div>
    
    <h2>Recent Observations</h2>
    <table>
        <tr><th>Program</th><th>Method</th><th>Path</th><th>Status</th><th>Auth</th><th>Created</th></tr>
""".format(search)
    
    for row in obs_rows:
        html += f"<tr><td>{row['program']}</td><td>{row['method']}</td><td>{row['path']}</td><td>{row['status_code']}</td><td>{row['auth_state']}</td><td>{row['created_at']}</td></tr>"
    
    html += """
    </table>
    
    <h2>Recent Traces with Risk Score</h2>
    <table>
        <tr><th>Trace ID</th><th>Created</th><th>Program</th><th>Method</th><th>Path</th><th>Risk Score</th><th>Actions</th></tr>
"""
    
    for row in trace_rows:
        score = row['max_risk_score'] or 0
        css_class = "critical" if score > 80 else "high" if score > 60 else "medium" if score > 30 else ""
        html += f"<tr class='{css_class}'>"
        html += f"<td><a href='/trace/{row['trace_id']}'>{row['trace_id']}</a></td>"
        html += f"<td>{row['created_at']}</td><td>{row['program']}</td><td>{row['method']}</td><td>{row['path']}</td>"
        html += f"<td>{score}</td>"
        html += f"<td><a href='/trace/{row['trace_id']}/report?format=markdown'>Markdown</a> | <a href='/trace/{row['trace_id']}/report'>JSON</a></td>"
        html += "</tr>"
    
    html += """
    </table>
    
    <h2>High-Value Endpoints (Score > 70)</h2>
    <table>
        <tr><th>Normalized Path</th><th>Family</th><th>Score</th><th>Created</th></tr>
"""
    
    for row in intel_rows:
        score = row['score']
        css_class = "critical" if score > 85 else "high" if score > 75 else "medium"
        html += f"<tr class='{css_class}'>"
        html += f"<td>{row['normalized_path']}</td><td>{row['family']}</td><td>{row['score']}</td><td>{row['created_at']}</td></tr>"
    
    html += """
    </table>
</body>
</html>
"""
    return html

# ============================================
# EXTEND HEALTH CHECK
# ============================================

@app.route("/health/detailed", methods=["GET"])
@require_api_key
def health_detailed():
    """Detailed health check with database stats."""
    conn = get_db()
    
    stats = {}
    tables = ["observations", "trace_runs", "attack_paths", "pivot_attempts", 
              "endpoint_graph_nodes", "endpoint_graph_edges", "endpoint_intelligence"]
    for table in tables:
        try:
            count = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()["cnt"]
            stats[table] = count
        except:
            stats[table] = "error"
    
    conn.close()
    
    return jsonify({
        "ok": True,
        "service": "hex-workbench",
        "version": "1.0",
        "database": DB_PATH,
        "stats": stats,
        "config": {
            "auto_mutation_enabled": AUTO_MUTATION_ENABLED,
            "auto_exploit_replay_enabled": AUTO_EXPLOIT_REPLAY_ENABLED,
            "multi_auth_enabled": MULTI_AUTH_ENABLED,
            "allowed_hosts": ALLOWED_TARGET_HOSTS,
            "allow_private_hosts": ALLOW_PRIVATE_HOSTS,
            "allow_localhost": ALLOW_LOCALHOST_TARGETS
        }
    })

@app.route('/favicon.ico')
def favicon():
    return '', 204   # No content, silent

@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception("Unhandled exception: %s", e)
    return jsonify({
        "ok": False,
        "error": "internal_error",
        "message": str(e)
    }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
