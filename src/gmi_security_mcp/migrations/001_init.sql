-- Migration 001: findings store schema v1.
-- Phase A2 (v0.5.0). SQLite, Python sqlite3 stdlib, no new dependency.
-- Adapted in shape from 0sec-labs/0 packages/db schema (scans,
-- targets, findings, verdicts, pipelineEvents, triageMemories,
-- cases, workItems, artifacts), written as SQL here, not copied.
-- Additions over the plan list, needed by the tools: findings.code
-- (redacted code, never a full secret), findings.evidence_json,
-- and a verifications table, so mark_confirmed can check for a
-- reproduced verification result. Business impact is stored as
-- JSON text in findings.business_impact.

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
