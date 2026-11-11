"""SQLite findings store, Phase A2 (v0.5.0).

A finding has a history: scan to fix, with verdicts, pipeline
events, verification results, business impact, and triage
memories. Python sqlite3 stdlib only, no new dependency.

Sources: Python sqlite3 docs (WAL mode, foreign keys pragma,
one connection per operation, no shared global connection);
migrations as numbered SQL files in migrations/, tracked by a
schema_version table. Schema shape adapted from 0sec-labs/0
packages/db (commit a891ba1, dual MIT OR Apache-2.0), written
here as Python and SQL, not copied. See NOTICE.

Rules enforced here:
- Default DB is per-user ~/.gmi-security-mcp/findings.db. Never
  commit findings or the DB. An explicit db_path is allowed only
  with a warning that the caller is responsible for not
  committing it.
- Finding status values, exact: new, triaged, verified,
  confirmed, false_positive, suppressed, fixed. Moves only
  forward, except false_positive and suppressed can move back to
  triaged when a new scan finds the same code again, with the
  history retained. Every status change is a pipeline event
  with actor and time, never silent. Transition rules live in
  validate.validate_status_transition; this module applies them.
- Suppression guard (isDisclosureWorthy): suppressing a
  critical/high finding with business impact Urgent/High is
  refused unless force is true and a reason is given. A
  suppressed finding stays visible, never deleted.
- Triage memories are hints, never auto-reject. A memory is
  created only by a human mark_fp call, never by the server
  alone. matching_memories returns memories that match a finding
  exactly by scope; the caller must still triage.
- Business impact is operator-editable and changes business
  impact only, never technical severity, verification, review
  gates, or patch permissions.
- Code stored here is redacted before it reaches this module
  by the caller (see server.py); this module never un-redacts
  anything, and artifacts hold sha256 hashes only, never a
  full secret, never a key.
"""

import base64
import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1
DEFAULT_DIR_NAME = ".gmi-security-mcp"
DEFAULT_DB_NAME = "findings.db"

# Fallback schema, used only when migrations/001_init.sql cannot
# be found. Since v0.5.8 the migration ships inside the package,
# so the fallback is a last resort only. It is identical to that
# file; the file is the source of truth and this copy is kept in
# step with it.
_FALLBACK_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    stage1_model TEXT,
    stage2_model TEXT,
    spend_cap_usd REAL,
    total_cost_usd REAL NOT NULL DEFAULT 0,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    findings_total INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running'
);
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL UNIQUE,
    scope_file TEXT,
    created_at TEXT NOT NULL,
    last_scan_id TEXT REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id),
    "check" TEXT NOT NULL DEFAULT '',
    file TEXT NOT NULL DEFAULT '',
    line INTEGER,
    code TEXT NOT NULL DEFAULT '',
    code_hash TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    verdict TEXT,
    severity TEXT NOT NULL DEFAULT 'low',
    confidence REAL,
    reason TEXT NOT NULL DEFAULT '',
    fix TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'new',
    business_impact TEXT NOT NULL DEFAULT '{"label": "Not assessed", "affected_customers": "", "affected_services": "", "affected_data": "", "rationale": ""}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_code_hash
    ON findings(code_hash, "check", file);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS verdicts (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    model TEXT,
    stage TEXT,
    verdict TEXT,
    severity TEXT NOT NULL DEFAULT 'low',
    confidence REAL,
    reason TEXT NOT NULL DEFAULT '',
    fix TEXT NOT NULL DEFAULT '',
    latency_seconds REAL,
    usage_json TEXT NOT NULL DEFAULT '{}',
    cost_usd REAL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_finding ON verdicts(finding_id);
CREATE TABLE IF NOT EXISTS pipelineEvents (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    event TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'server'
);
CREATE INDEX IF NOT EXISTS idx_events_finding ON pipelineEvents(finding_id);
CREATE TABLE IF NOT EXISTS triageMemories (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL DEFAULT 'target',
    package TEXT,
    target TEXT,
    rule_id TEXT,
    "check" TEXT,
    verdict TEXT NOT NULL DEFAULT 'false_positive',
    reason TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'human',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memories_check ON triageMemories("check");
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    finding_ids_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workItems (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id),
    finding_id TEXT REFERENCES findings(id),
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    path TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verifications (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    status TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    assertions_json TEXT NOT NULL DEFAULT '[]',
    artifacts_json TEXT NOT NULL DEFAULT '[]',
    poc_before_json TEXT NOT NULL DEFAULT '{}',
    poc_after_json TEXT,
    model TEXT,
    cost_usd REAL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verifications_finding
    ON verifications(finding_id);
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (1, datetime('now'));
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix):
    return "%s_%s" % (prefix, uuid.uuid4().hex[:16])


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def default_db_path():
    """Per-user default DB path. Never inside a repo."""
    return Path.home() / DEFAULT_DIR_NAME / DEFAULT_DB_NAME


def resolve_db_path(db_path):
    """Resolve a db_path argument to (Path, warning or None).

    None means the per-user default, with no warning. An explicit
    path is allowed, but the result always carries a warning that
    the caller is responsible for not committing the DB, because
    findings can contain code and secrets.
    """
    if db_path is None:
        return default_db_path(), None
    path = Path(str(db_path)).expanduser()
    warning = (
        "Explicit db_path %s: findings can contain code and "
        "secrets. You are responsible for not committing this "
        "database file to any repo." % path
    )
    return path, warning


def _migration_sql():
    candidates = [
        Path(__file__).resolve().parents[2] / "migrations" / "001_init.sql",
        Path(__file__).resolve().parent / "migrations" / "001_init.sql",
    ]
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate.read_text()
        except OSError:
            continue
    return _FALLBACK_SCHEMA


def migrate(conn):
    """Apply schema v1 to a connection. Idempotent: a fresh DB
    migrates to v1, and a DB with data keeps its rows."""
    conn.executescript(_migration_sql())
    conn.commit()
    row = conn.execute(
        "SELECT MAX(version) FROM schema_version"
    ).fetchone()
    return row[0] if row and row[0] is not None else 0


def schema_version(conn):
    row = conn.execute(
        "SELECT MAX(version) FROM schema_version"
    ).fetchone()
    return row[0] if row and row[0] is not None else 0


@contextmanager
def connect(db_path=None):
    """One connection per use, WAL mode, foreign keys on.

    The connection is created, migrated, yielded, committed,
    and closed by this context manager. No shared global
    connection is kept. Resolving None creates the per-user
    default directory and file.
    """
    path, _warning = resolve_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        migrate(conn)
        yield conn
        conn.commit()
    finally:
        conn.close()


def _row_to_dict(row):
    return dict(row) if row is not None else None


def _parse_business_impact(raw):
    try:
        data = json.loads(raw or "{}")
    except (ValueError, TypeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {
        "label": data.get("label") or "Not assessed",
        "affected_customers": data.get("affected_customers") or "",
        "affected_services": data.get("affected_services") or "",
        "affected_data": data.get("affected_data") or "",
        "rationale": data.get("rationale") or "",
    }


def _finding_to_dict(row):
    data = _row_to_dict(row)
    if data is None:
        return None
    data["business_impact"] = _parse_business_impact(
        data.get("business_impact")
    )
    try:
        data["evidence"] = json.loads(data.pop("evidence_json") or "{}")
    except (ValueError, TypeError):
        data["evidence"] = {}
    return data


# --- scans and targets -------------------------------------------


def insert_scan(conn, repo_path, stage1_model=None, stage2_model=None,
                spend_cap_usd=None):
    scan_id = new_id("scn")
    conn.execute(
        "INSERT INTO scans (id, repo_path, started_at, stage1_model,"
        " stage2_model, spend_cap_usd, status)"
        " VALUES (?, ?, ?, ?, ?, ?, 'running')",
        (
            scan_id,
            str(repo_path),
            now_iso(),
            stage1_model,
            stage2_model,
            spend_cap_usd,
        ),
    )
    return scan_id


def finish_scan(conn, scan_id, total_cost_usd=0.0, files_scanned=0,
                findings_total=0, status="completed"):
    conn.execute(
        "UPDATE scans SET finished_at = ?, total_cost_usd = ?,"
        " files_scanned = ?, findings_total = ?, status = ?"
        " WHERE id = ?",
        (
            now_iso(),
            total_cost_usd,
            files_scanned,
            findings_total,
            status,
            scan_id,
        ),
    )


def get_scan(conn, scan_id):
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    return _row_to_dict(row)


def upsert_target(conn, repo_path, scope_file=None, last_scan_id=None):
    now = now_iso()
    row = conn.execute(
        "SELECT id FROM targets WHERE repo_path = ?",
        (str(repo_path),),
    ).fetchone()
    if row is not None:
        conn.execute(
            "UPDATE targets SET scope_file = COALESCE(?, scope_file),"
            " last_scan_id = COALESCE(?, last_scan_id) WHERE id = ?",
            (scope_file, last_scan_id, row["id"]),
        )
        return row["id"]
    target_id = new_id("tgt")
    conn.execute(
        "INSERT INTO targets (id, repo_path, scope_file, created_at,"
        " last_scan_id) VALUES (?, ?, ?, ?, ?)",
        (target_id, str(repo_path), scope_file, now, last_scan_id),
    )
    return target_id


# --- findings ------------------------------------------------------


def find_by_code(conn, code_hash, check, file):
    """Existing finding for the same redacted code, check, and
    file, or None. Used to deduplicate a re-scan of the same code
    and to reopen a false_positive or suppressed finding."""
    row = conn.execute(
        "SELECT * FROM findings WHERE code_hash = ? AND \"check\" = ?"
        " AND file = ? ORDER BY created_at DESC LIMIT 1",
        (code_hash, check or "", file or ""),
    ).fetchone()
    return _finding_to_dict(row)


def insert_finding(conn, scan_id=None, check="", file="", line=None,
                   code="", code_hash=None, evidence=None,
                   verdict=None, severity="low", confidence=None,
                   reason="", fix="", status="new",
                   business_impact=None):
    """Insert a finding, or reopen/refresh the existing one for
    the same code. Returns (finding_id, was_reopened).

    A re-scan that finds the same code again moves a
    false_positive or suppressed finding back to triaged, with
    a pipeline event, and keeps the history. Any other existing
    finding keeps its id and gets its verdict fields refreshed.
    """
    redacted_code = code or ""
    digest = code_hash or sha256_hex(redacted_code)
    existing = find_by_code(conn, digest, check or "", file or "")
    now = now_iso()
    impact = business_impact or {
        "label": "Not assessed",
        "affected_customers": "",
        "affected_services": "",
        "affected_data": "",
        "rationale": "",
    }
    if existing is not None:
        finding_id = existing["id"]
        was_reopened = existing["status"] in (
            "false_positive",
            "suppressed",
        )
        new_status = existing["status"]
        if was_reopened or (
            verdict is not None and existing["status"] == "new"
        ):
            new_status = "triaged"
        conn.execute(
            "UPDATE findings SET scan_id = COALESCE(?, scan_id),"
            " verdict = ?, severity = ?, confidence = ?, reason = ?,"
            " fix = ?, status = ?, updated_at = ? WHERE id = ?",
            (
                scan_id,
                verdict,
                severity or "low",
                confidence,
                reason or "",
                fix or "",
                new_status,
                now,
                finding_id,
            ),
        )
        if was_reopened:
            insert_event(
                conn,
                finding_id,
                "reopened_on_rescan",
                "Same code found again on a new scan; status moved "
                "back to triaged. Earlier history is retained.",
                actor="server",
            )
        return finding_id, was_reopened
    finding_id = new_id("fnd")
    conn.execute(
        "INSERT INTO findings (id, scan_id, \"check\", file, line, code,"
        " code_hash, evidence_json, verdict, severity, confidence,"
        " reason, fix, status, business_impact, created_at,"
        " updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
        " ?, ?, ?, ?, ?)",
        (
            finding_id,
            scan_id,
            check or "",
            file or "",
            line,
            redacted_code,
            digest,
            json.dumps(evidence or {}),
            verdict,
            severity or "low",
            confidence,
            reason or "",
            fix or "",
            status,
            json.dumps(impact),
            now,
            now,
        ),
    )
    insert_event(
        conn,
        finding_id,
        "created",
        "Finding stored with status %s." % status,
        actor="server",
    )
    return finding_id, False


def get_finding(conn, finding_id):
    row = conn.execute(
        "SELECT * FROM findings WHERE id = ?", (str(finding_id),)
    ).fetchone()
    return _finding_to_dict(row)


def list_findings(conn, status=None, check=None, severity=None,
                  repo_path=None, limit=20, cursor=None):
    """Finding summaries, newest first. No code in list output.

    cursor is an opaque offset: base64 of the integer offset.
    Returns (summaries, next_cursor or None, total).
    """
    limit = max(1, min(int(limit or 20), 100))
    offset = 0
    if cursor:
        try:
            offset = int(base64.urlsafe_b64decode(
                str(cursor).encode()).decode())
        except (ValueError, TypeError, base64.binascii.Error):
            offset = 0
    clauses = []
    params = []
    if status:
        clauses.append("f.status = ?")
        params.append(status)
    if check:
        clauses.append('f."check" = ?')
        params.append(check)
    if severity:
        clauses.append("f.severity = ?")
        params.append(severity)
    if repo_path:
        clauses.append("s.repo_path = ?")
        params.append(str(repo_path))
    # The WHERE clause is built only from fixed clause strings
    # above; every filter value is a bound parameter, never
    # interpolated into the SQL text. No caller input reaches
    # the query as text.
    where_parts = ["WHERE " + " AND ".join(clauses)] if clauses else []
    count_sql = " ".join(
        [
            "SELECT COUNT(*) FROM findings f",
            "LEFT JOIN scans s ON f.scan_id = s.id",
        ]
        + where_parts
    )
    total_row = conn.execute(count_sql, params).fetchone()
    total = total_row[0] if total_row else 0
    select_sql = " ".join(
        [
            "SELECT f.id, f.\"check\", f.file, f.line, f.verdict,",
            "f.severity, f.confidence, f.status, f.business_impact,",
            "f.created_at, f.updated_at FROM findings f",
            "LEFT JOIN scans s ON f.scan_id = s.id",
        ]
        + where_parts
        + [
            "ORDER BY f.created_at DESC, f.id DESC LIMIT ? OFFSET ?",
        ]
    )
    rows = conn.execute(
        select_sql,
        params + [limit, offset],
    ).fetchall()
    summaries = []
    for row in rows:
        item = _row_to_dict(row)
        item["business_impact"] = _parse_business_impact(
            item.get("business_impact")
        )
        summaries.append(item)
    next_cursor = None
    if offset + len(summaries) < total:
        next_cursor = base64.urlsafe_b64encode(
            str(offset + limit).encode()).decode()
    return summaries, next_cursor, total


def get_finding_full(conn, finding_id):
    """Full finding: code, evidence, verdict history, pipeline
    events, verification results, business impact, and matching
    triage memories. Returns None when the finding is not found.
    """
    finding = get_finding(conn, finding_id)
    if finding is None:
        return None
    verdict_rows = conn.execute(
        "SELECT * FROM verdicts WHERE finding_id = ?"
        " ORDER BY created_at ASC",
        (finding_id,),
    ).fetchall()
    verdicts = []
    for row in verdict_rows:
        item = _row_to_dict(row)
        try:
            item["usage"] = json.loads(item.pop("usage_json") or "{}")
        except (ValueError, TypeError):
            item["usage"] = {}
        verdicts.append(item)
    event_rows = conn.execute(
        "SELECT * FROM pipelineEvents WHERE finding_id = ?"
        " ORDER BY created_at ASC",
        (finding_id,),
    ).fetchall()
    events = [_row_to_dict(r) for r in event_rows]
    verification_rows = conn.execute(
        "SELECT * FROM verifications WHERE finding_id = ?"
        " ORDER BY created_at ASC",
        (finding_id,),
    ).fetchall()
    verifications = []
    for row in verification_rows:
        item = _row_to_dict(row)
        item["confirmed"] = bool(item.get("confirmed"))
        for key in ("assertions_json", "artifacts_json",
                    "poc_before_json", "poc_after_json"):
            try:
                item[key.replace("_json", "")] = json.loads(
                    item.pop(key) or ("{}" if "poc" in key else "[]")
                )
            except (ValueError, TypeError):
                item[key.replace("_json", "")] = (
                    {} if "poc" in key else []
                )
        verifications.append(item)
    artifact_rows = conn.execute(
        "SELECT * FROM artifacts WHERE finding_id = ?"
        " ORDER BY created_at ASC",
        (finding_id,),
    ).fetchall()
    finding["verdicts"] = verdicts
    finding["pipeline_events"] = events
    finding["verifications"] = verifications
    finding["artifacts"] = [_row_to_dict(r) for r in artifact_rows]
    finding["triage_memories"] = matching_memories(conn, finding)
    return finding


# --- verdicts, events, memories, cases, artifacts, verifications -


def insert_verdict(conn, finding_id, model=None, stage=None,
                   verdict=None, severity="low", confidence=None,
                   reason="", fix="", latency_seconds=None,
                   usage=None, cost_usd=None):
    verdict_id = new_id("vrd")
    conn.execute(
        "INSERT INTO verdicts (id, finding_id, model, stage,"
        " verdict, severity, confidence, reason, fix,"
        " latency_seconds, usage_json, cost_usd, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            verdict_id,
            finding_id,
            model,
            stage,
            verdict,
            severity or "low",
            confidence,
            reason or "",
            fix or "",
            latency_seconds,
            json.dumps(usage or {}),
            cost_usd,
            now_iso(),
        ),
    )
    return verdict_id


def insert_event(conn, finding_id, event, detail="", actor="server"):
    event_id = new_id("evt")
    conn.execute(
        "INSERT INTO pipelineEvents (id, finding_id, event, detail,"
        " created_at, actor) VALUES (?, ?, ?, ?, ?, ?)",
        (
            event_id,
            finding_id,
            event,
            detail or "",
            now_iso(),
            actor,
        ),
    )
    return event_id


def insert_memory(conn, scope="target", package=None, target=None,
                  rule_id=None, check=None, verdict="false_positive",
                  reason="", created_by="human"):
    """Create a triage memory. Callers must only call this from
    a human mark_fp; the server never creates a memory alone."""
    memory_id = new_id("mem")
    conn.execute(
        "INSERT INTO triageMemories (id, scope, package, target,"
        " rule_id, \"check\", verdict, reason, created_by, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            memory_id,
            scope,
            package,
            target,
            rule_id,
            check,
            verdict,
            reason or "",
            created_by,
            now_iso(),
        ),
    )
    return memory_id


def _package_of_finding(finding):
    """Package for scope matching: the top-level directory of
    the finding file, or the repo name when the file is at the
    repo root."""
    file_path = (finding.get("file") or "").strip("/")
    parts = [p for p in file_path.split("/") if p]
    if len(parts) > 1:
        return parts[0]
    return None


def matching_memories(conn, finding):
    """Memories that match a finding exactly by scope, as hints.

    global matches any finding; target matches when the memory
    target is the finding's repo path; package matches when the
    memory package is the finding's top-level directory. A
    memory with a check set only matches that check. Matching
    never changes the finding's verdict.
    """
    rows = conn.execute(
        "SELECT * FROM triageMemories ORDER BY created_at ASC"
    ).fetchall()
    repo_path = None
    scan_id = finding.get("scan_id")
    if scan_id:
        scan = get_scan(conn, scan_id)
        if scan:
            repo_path = scan.get("repo_path")
    package = _package_of_finding(finding)
    matches = []
    for row in rows:
        item = _row_to_dict(row)
        if item.get("check") and item["check"] != finding.get("check"):
            continue
        scope = item.get("scope")
        if scope == "global":
            matches.append(item)
        elif scope == "target" and item.get("target") and repo_path:
            if item["target"] == repo_path:
                matches.append(item)
        elif scope == "package" and item.get("package") and package:
            if item["package"] == package:
                matches.append(item)
    return matches


def insert_case(conn, title, finding_ids=None, status="open"):
    case_id = new_id("case")
    now = now_iso()
    conn.execute(
        "INSERT INTO cases (id, title, finding_ids_json, status,"
        " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            case_id,
            title,
            json.dumps(finding_ids or []),
            status,
            now,
            now,
        ),
    )
    return case_id


def insert_work_item(conn, case_id=None, finding_id=None, title="",
                     status="open"):
    item_id = new_id("wi")
    now = now_iso()
    conn.execute(
        "INSERT INTO workItems (id, case_id, finding_id, title,"
        " status, created_at, updated_at) VALUES (?, ?, ?, ?, ?,"
        " ?, ?)",
        (item_id, case_id, finding_id, title, status, now, now),
    )
    return item_id


def insert_artifact(conn, finding_id, name, sha256, path=None):
    """Store an artifact descriptor: name and sha256 only, never
    a full secret, never a key."""
    artifact_id = new_id("art")
    conn.execute(
        "INSERT INTO artifacts (id, finding_id, name, sha256, path,"
        " created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            artifact_id,
            finding_id,
            name,
            sha256,
            path,
            now_iso(),
        ),
    )
    return artifact_id


def insert_verification(conn, finding_id, result):
    """Store a VerificationResult dict. Returns the verification
    id. Artifact descriptors from the result are also stored in
    the artifacts table, as hashes only."""
    verification_id = new_id("ver")
    conn.execute(
        "INSERT INTO verifications (id, finding_id, status,"
        " confirmed, assertions_json, artifacts_json,"
        " poc_before_json, poc_after_json, model, cost_usd,"
        " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            verification_id,
            finding_id,
            result.get("status"),
            1 if result.get("confirmed") else 0,
            json.dumps(result.get("assertions") or []),
            json.dumps(result.get("artifacts") or []),
            json.dumps(result.get("poc_before") or {}),
            (
                json.dumps(result["poc_after"])
                if result.get("poc_after") is not None else None
            ),
            result.get("model"),
            result.get("cost_usd"),
            now_iso(),
        ),
    )
    for artifact in result.get("artifacts") or []:
        insert_artifact(
            conn,
            finding_id,
            artifact.get("name"),
            artifact.get("sha256"),
            artifact.get("path"),
        )
    return verification_id


def has_reproduced_verification(conn, finding_id):
    row = conn.execute(
        "SELECT id FROM verifications WHERE finding_id = ?"
        " AND status = 'reproduced' ORDER BY created_at DESC LIMIT 1",
        (finding_id,),
    ).fetchone()
    return row["id"] if row is not None else None


# --- status changes -------------------------------------------------


def update_finding_status(conn, finding_id, target_status,
                          reason, actor="server", force=False,
                          has_verification=False):
    """Move a finding to a new status, with the transition rules
    from validate.validate_status_transition.

    Returns (finding dict or None, error or None). Every change
    writes a pipeline event. A refusal writes nothing.
    """
    from . import validate as validate_mod

    finding = get_finding(conn, finding_id)
    if finding is None:
        return None, "finding %s was not found in the store" % finding_id
    current = finding["status"]
    ok, error = validate_mod.validate_status_transition(
        current, target_status,
        has_verification=has_verification,
    )
    if not ok:
        return None, error
    if target_status == "suppressed":
        impact = finding["business_impact"]
        label = impact.get("label")
        severity = finding.get("severity")
        if severity in ("critical", "high") and label in (
            "Urgent",
            "High",
        ):
            if not force or not (reason or "").strip():
                return None, (
                    "Refusing to suppress a %s finding with "
                    "business impact %s. This finding is "
                    "disclosure-worthy and is held for further "
                    "verification instead of dropped. Pass "
                    "force true with a reason to suppress it "
                    "anyway; the suppression is then recorded "
                    "with that reason and actor."
                    % (severity, label)
                )
    conn.execute(
        "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
        (target_status, now_iso(), finding_id),
    )
    detail = "Status %s to %s. Reason: %s" % (
        current, target_status, reason or ""
    )
    if target_status == "suppressed" and force:
        detail += " (forced suppression of a disclosure-worthy finding)"
    insert_event(conn, finding_id, "status_change", detail, actor=actor)
    return get_finding(conn, finding_id), None


def update_business_impact(conn, finding_id, business_impact,
                           reason, actor="server"):
    """Change business impact only. Technical severity,
    verification results, review gates, and patch permissions
    are never touched by this function.

    Returns (finding dict or None, error or None).
    """
    from . import validate as validate_mod

    clean = validate_mod.norm_business_impact(business_impact)
    if clean is None:
        return None, (
            "business_impact must be an object with a label of "
            "Urgent, High, Moderate, Low, or Not assessed"
        )
    finding = get_finding(conn, finding_id)
    if finding is None:
        return None, "finding %s was not found in the store" % finding_id
    conn.execute(
        "UPDATE findings SET business_impact = ?, updated_at = ?"
        " WHERE id = ?",
        (json.dumps(clean), now_iso(), finding_id),
    )
    insert_event(
        conn,
        finding_id,
        "business_impact_updated",
        "Business impact set to %s. Reason: %s. This changes "
        "business impact only, not technical severity, "
        "verification, review gates, or patch permissions."
        % (clean["label"], reason or ""),
        actor=actor,
    )
    return get_finding(conn, finding_id), None
