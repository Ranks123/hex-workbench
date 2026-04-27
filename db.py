import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "workbench.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program TEXT NOT NULL,
        user_label TEXT NOT NULL,
        method TEXT NOT NULL,
        scheme TEXT,
        host TEXT NOT NULL,
        path TEXT NOT NULL,
        query_string TEXT,
        status_code INTEGER,
        auth_state TEXT NOT NULL,
        content_type TEXT,
        response_content_type TEXT,
        response_length INTEGER NOT NULL DEFAULT 0,
        request_hash TEXT,
        response_fingerprint TEXT,
        source_tool TEXT,
        source_note TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS parameters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        observation_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        source TEXT NOT NULL,
        value_type TEXT,
        classification TEXT,
        sample_value TEXT,
        FOREIGN KEY(observation_id) REFERENCES observations(id)
    )
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_obs_program_host_path_method
    ON observations(program, host, path, method)
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_obs_auth_state
    ON observations(auth_state)
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_obs_status_code
    ON observations(status_code)
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_obs_created_at
    ON observations(created_at)
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_params_observation_id
    ON parameters(observation_id)
    """)

    conn.commit()
    conn.close()


def add_observation(row: dict, parameters: list):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO observations (
        program, user_label, method, scheme, host, path, query_string,
        status_code, auth_state, content_type, response_content_type,
        response_length, request_hash, response_fingerprint,
        source_tool, source_note
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        row["program"], row["user_label"], row["method"], row["scheme"],
        row["host"], row["path"], row["query_string"], row["status_code"],
        row["auth_state"], row["content_type"], row["response_content_type"],
        row["response_length"], row["request_hash"], row["response_fingerprint"],
        row["source_tool"], row["source_note"]
    ))

    observation_id = cur.lastrowid

    for p in parameters:
        cur.execute("""
        INSERT INTO parameters (
            observation_id, name, source, value_type, classification, sample_value
        ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            observation_id,
            p.get("name", ""),
            p.get("source", ""),
            p.get("value_type"),
            p.get("classification"),
            p.get("sample_value", "")
        ))

    conn.commit()
    conn.close()
    return observation_id


def recent_for_endpoint(program: str, method: str, host: str, path: str, limit: int = 10):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    SELECT *
    FROM observations
    WHERE program = ? AND method = ? AND host = ? AND path = ?
    ORDER BY id DESC
    LIMIT ?
    """, (program, method, host, path, limit))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def program_summary(program: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT COUNT(*) AS total_observations
    FROM observations
    WHERE program = ?
    """, (program,))
    total = dict(cur.fetchone())["total_observations"]

    cur.execute("""
    SELECT host, COUNT(*) AS seen_count
    FROM observations
    WHERE program = ?
    GROUP BY host
    ORDER BY seen_count DESC
    """, (program,))
    hosts = [dict(r) for r in cur.fetchall()]

    cur.execute("""
    SELECT method, path, COUNT(*) AS seen_count
    FROM observations
    WHERE program = ?
    GROUP BY method, path
    ORDER BY seen_count DESC, method, path
    LIMIT 50
    """, (program,))
    endpoints = [dict(r) for r in cur.fetchall()]

    cur.execute("""
    SELECT auth_state, COUNT(*) AS seen_count
    FROM observations
    WHERE program = ?
    GROUP BY auth_state
    ORDER BY seen_count DESC
    """, (program,))
    auth_states = [dict(r) for r in cur.fetchall()]

    conn.close()

    return {
        "program": program,
        "total_observations": total,
        "hosts": hosts,
        "top_endpoints": endpoints,
        "auth_states": auth_states,
    }


def endpoint_parameter_summary(program: str, method: str, host: str, path: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT
        p.name,
        p.source,
        p.value_type,
        p.classification,
        COUNT(*) AS seen_count
    FROM parameters p
    JOIN observations o ON p.observation_id = o.id
    WHERE o.program = ? AND o.method = ? AND o.host = ? AND o.path = ?
    GROUP BY p.name, p.source, p.value_type, p.classification
    ORDER BY seen_count DESC, p.name ASC
    """, (program, method, host, path))

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def endpoint_auth_delta(program: str, method: str, host: str, path: str):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT
        auth_state,
        COUNT(*) AS seen_count,
        MIN(status_code) AS min_status,
        MAX(status_code) AS max_status,
        MIN(response_length) AS min_response_length,
        MAX(response_length) AS max_response_length
    FROM observations
    WHERE program = ? AND method = ? AND host = ? AND path = ?
    GROUP BY auth_state
    ORDER BY seen_count DESC
    """, (program, method, host, path))

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def recent_program_activity(program: str, limit: int = 20):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT *
    FROM observations
    WHERE program = ?
    ORDER BY id DESC
    LIMIT ?
    """, (program, limit))

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
