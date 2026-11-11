"""Unit tests for the Phase A2 findings store, SQLite, no GMI calls.

The chat function is a deterministic MockLLM stub that returns a
fixed verdict, labelled mockllm in the test names and in the log
lines. MockLLM proves the code does not crash and the store
writes; it is a regression floor, never a live accuracy claim.
Dataset-v2 (56 findings) runs under MockLLM only in this cut,
never live, never reported as live accuracy.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import server as srv
from gmi_security_mcp import store as store_mod
from gmi_security_mcp import validate as validate_mod

PRICING = {
    "google/gemini-3.5-flash-lite": (0.000000300, 0.000002500),
    "Qwen/Qwen3.8-Flash": (0.000000160, 0.000000470),
}
CHEAP = "google/gemini-3.5-flash-lite"
QWEN = "Qwen/Qwen3.8-Flash"

os.environ["GMI_API_KEY"] = "test-key-never-sent"

ROOT = Path(__file__).resolve().parents[1]


def _mockllm_chat(verdict="real", confidence=0.9, severity="high"):
    """Deterministic MockLLM: one fixed verdict, no network."""
    def _call(model, system_content, user_content, max_tokens=2500):
        return {
            "content": json.dumps(
                {
                    "verdict": verdict,
                    "severity": severity,
                    "confidence": confidence,
                    "reason": "MockLLM fixed verdict for the store floor.",
                    "fix": "Fix it.",
                }
            ),
            "latency_seconds": 0.5,
            "usage": {"prompt_tokens": 200, "completion_tokens": 20},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    return _call


def _db(tmp_path):
    return str(tmp_path / "findings.db")


def _finding_dict(**over):
    data = {
        "verdict": "real",
        "severity": "high",
        "confidence": 0.9,
        "reason": "Input reaches the sink.",
        "fix": "Use parameters.",
        "check": "SQL injection",
        "line": 5,
    }
    data.update(over)
    return data


def _insert_finding(conn, **over):
    args = {
        "check": "SQL injection",
        "file": "src/app.py",
        "line": 5,
        "code": "query = x + user_input",
        "verdict": "real",
        "severity": "high",
        "confidence": 0.9,
        "reason": "Input reaches the sink.",
        "fix": "Use parameters.",
        "status": "new",
    }
    args.update(over)
    return store_mod.insert_finding(conn, **args)


def _reproduced_result():
    return {
        "finding_id": None,
        "status": "reproduced",
        "confirmed": True,
        "assertions": [
            {"name": "oracle", "passed": True, "detail": "reproduced"}
        ],
        "artifacts": [
            {
                "name": "poc",
                "sha256": "a" * 64,
                "path": None,
            }
        ],
        "poc_before": {
            "command": ["python3", "poc.py"],
            "exit_code": 0,
            "output_hash": "b" * 64,
            "ran": True,
        },
        "poc_after": None,
        "model": None,
        "usage": {},
        "cost_usd": 0.0,
        "estimate_usd": 0.0,
        "unparsed": False,
        "error": None,
    }


# --- schema, CRUD, migration ----------------------------------------


def test_store_schema_crud_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        assert store_mod.schema_version(conn) == 1
        scan_id = store_mod.insert_scan(
            conn, "/tmp/repo", CHEAP, QWEN, 1.00
        )
        target_id = store_mod.upsert_target(
            conn, "/tmp/repo", last_scan_id=scan_id
        )
        assert target_id
        finding_id, _reopened = _insert_finding(conn, scan_id=scan_id)
        verdict_id = store_mod.insert_verdict(
            conn, finding_id, model=CHEAP, stage="stage1",
            verdict="real", severity="high", confidence=0.9,
            reason="Input reaches the sink.", fix="Use parameters.",
            latency_seconds=0.5,
            usage={"prompt_tokens": 200, "completion_tokens": 20},
            cost_usd=0.0001,
        )
        event_id = store_mod.insert_event(
            conn, finding_id, "created", "stored", actor="server"
        )
        memory_id = store_mod.insert_memory(
            conn, scope="target", target="/tmp/repo",
            check="SQL injection", reason="not exploitable here",
        )
        case_id = store_mod.insert_case(
            conn, "SQLi in app", finding_ids=[finding_id]
        )
        work_id = store_mod.insert_work_item(
            conn, case_id=case_id, finding_id=finding_id,
            title="Fix SQLi",
        )
        artifact_id = store_mod.insert_artifact(
            conn, finding_id, "poc", "c" * 64
        )
        assert verdict_id and event_id and memory_id
        assert case_id and work_id and artifact_id
        stored = store_mod.get_finding(conn, finding_id)
        assert stored["check"] == "SQL injection"
        assert stored["status"] == "new"
        assert stored["business_impact"]["label"] == "Not assessed"
        scan = store_mod.get_scan(conn, scan_id)
        assert scan["repo_path"] == "/tmp/repo"
        assert scan["status"] == "running"
        store_mod.finish_scan(
            conn, scan_id, total_cost_usd=0.0001, files_scanned=1,
            findings_total=1,
        )
        assert store_mod.get_scan(conn, scan_id)["status"] == "completed"


def test_store_migration_empty_db_mockllm(tmp_path):
    db = _db(tmp_path)
    assert not Path(db).exists()
    with store_mod.connect(db) as conn:
        assert store_mod.schema_version(conn) == 1
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    for name in (
        "scans", "targets", "findings", "verdicts",
        "pipelineEvents", "triageMemories", "cases", "workItems",
        "artifacts", "verifications", "schema_version",
    ):
        assert name in tables


def test_store_migration_db_with_data_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn)
    # Reopening migrates again; the finding must survive.
    with store_mod.connect(db) as conn:
        assert store_mod.schema_version(conn) == 1
        stored = store_mod.get_finding(conn, finding_id)
        assert stored is not None
        assert stored["check"] == "SQL injection"
        summaries, _cursor, total = store_mod.list_findings(conn)
        assert total == 1
        assert summaries[0]["id"] == finding_id


# --- status transitions ----------------------------------------------


def test_status_forward_moves_pass_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="new")
        finding, error = store_mod.update_finding_status(
            conn, finding_id, "triaged", "triaged by operator",
            actor="operator",
        )
        assert error is None
        assert finding["status"] == "triaged"
        finding, error = store_mod.update_finding_status(
            conn, finding_id, "verified", "oracle reproduced",
            actor="server",
        )
        assert error is None
        assert finding["status"] == "verified"
        store_mod.insert_verification(
            conn, finding_id, _reproduced_result()
        )
        finding, error = store_mod.update_finding_status(
            conn, finding_id, "confirmed", "oracle reproduced",
            actor="operator", has_verification=True,
        )
        assert error is None
        assert finding["status"] == "confirmed"
        finding, error = store_mod.update_finding_status(
            conn, finding_id, "fixed", "patched and re-tested",
            actor="operator",
        )
        assert error is None
        assert finding["status"] == "fixed"
        _finding, error = store_mod.update_finding_status(
            conn, finding_id, "triaged", "reopen",
            actor="operator",
        )
        assert error is not None
        assert "final" in error


def test_status_new_to_confirmed_refused_without_verification_mockllm(
    tmp_path,
):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="new")
        _finding, error = store_mod.update_finding_status(
            conn, finding_id, "confirmed", "looks real",
            actor="operator",
        )
        assert error is not None
        assert "cannot move to confirmed" in error
        assert "LLM verdict alone" in error
        assert store_mod.get_finding(conn, finding_id)["status"] == "new"


def test_status_verified_to_confirmed_needs_verification_mockllm(
    tmp_path,
):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="verified")
        _finding, error = store_mod.update_finding_status(
            conn, finding_id, "confirmed", "looks real",
            actor="operator",
        )
        assert error is not None
        finding, error = store_mod.update_finding_status(
            conn, finding_id, "confirmed", "oracle reproduced",
            actor="operator", has_verification=True,
        )
        assert error is None
        assert finding["status"] == "confirmed"


def test_status_verified_is_operator_set_without_verification_mockllm(
    tmp_path,
):
    """v0.5.6 gap 5(b), accepted design: verified is operator-set.

    triaged -> verified succeeds with has_verification False: no
    reproduced verification is needed. Only confirmed is gated:
    validate_status_transition refuses it without a reproduced
    verification, and mark_confirmed refuses it too. verified is
    the intermediate status verify_finding itself sets when its
    oracle reproduces, and the operator's own review step; the
    proof-backed status is confirmed, not verified. Requiring a
    verification_id for verified would block an operator
    recording an out-of-band verification, so the behaviour
    stays and this test pins it.
    """
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="triaged")
        finding, error = store_mod.update_finding_status(
            conn, finding_id, "verified", "operator reviewed",
            actor="operator", has_verification=False,
        )
        assert error is None
        assert finding["status"] == "verified"
        _finding, error = store_mod.update_finding_status(
            conn, finding_id, "confirmed", "looks real",
            actor="operator", has_verification=False,
        )
        assert error is not None
        assert "cannot move to confirmed" in error


def test_status_false_positive_reopened_on_rescan_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="triaged")
        store_mod.update_finding_status(
            conn, finding_id, "false_positive", "not exploitable",
            actor="human",
        )
        assert store_mod.get_finding(conn, finding_id)["status"] == (
            "false_positive"
        )
        same_id, reopened = _insert_finding(
            conn, status="new", verdict="real"
        )
        assert same_id == finding_id
        assert reopened is True
        assert store_mod.get_finding(conn, finding_id)["status"] == (
            "triaged"
        )
        full = store_mod.get_finding_full(conn, finding_id)
        events = [e["event"] for e in full["pipeline_events"]]
        assert "status_change" in events
        assert "reopened_on_rescan" in events


# --- suppression guard -------------------------------------------------


def test_suppression_guard_refuses_critical_urgent_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(
            conn, status="triaged", severity="critical",
            business_impact={
                "label": "Urgent",
                "affected_customers": "all",
                "affected_services": "api",
                "affected_data": "credentials",
                "rationale": "auth bypass in prod",
            },
        )
        _finding, error = store_mod.update_finding_status(
            conn, finding_id, "suppressed", "ignore it",
            actor="operator",
        )
        assert error is not None
        assert "disclosure-worthy" in error
        assert store_mod.get_finding(conn, finding_id)["status"] == (
            "triaged"
        )


def test_suppression_guard_force_with_reason_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(
            conn, status="triaged", severity="high",
            business_impact={
                "label": "High",
                "affected_customers": "all",
                "affected_services": "api",
                "affected_data": "sessions",
                "rationale": "needs a second look",
            },
        )
        finding, error = store_mod.update_finding_status(
            conn, finding_id, "suppressed",
            "accepted risk, tracked in case 7",
            actor="operator", force=True,
        )
        assert error is None
        assert finding["status"] == "suppressed"
        summaries, _cursor, total = store_mod.list_findings(
            conn, status="suppressed"
        )
        assert total == 1
        assert summaries[0]["id"] == finding_id
        full = store_mod.get_finding_full(conn, finding_id)
        assert any(
            "forced suppression" in e["detail"]
            for e in full["pipeline_events"]
        )


# --- triage memories -----------------------------------------------------


def test_triage_memory_hint_not_reject_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(
            conn, status="triaged", file="src/app.py"
        )
    # mark_fp_impl opens its own connection, so the insert
    # connection above must be closed first.
    result = srv.mark_fp_impl(
        finding_id, "test-only path, not reachable",
        scope="package", db_path=db,
    )
    assert result["error"] is None
    assert result["finding"]["status"] == "false_positive"
    assert result["memory_id"]
    # A new finding with the same check and package still gets a
    # real verdict from the MockLLM; the memory is only a hint.
    result = srv.triage_impl(
        finding="SQL injection in app",
        code="query = x + user_input",
        file="src/other.py",
        line=9,
        check="SQL injection",
        stage1_model=CHEAP,
        chat_fn=_mockllm_chat("real"),
        pricing=PRICING,
        db_path=db,
    )
    assert result["verdict"] == "real"
    assert result["finding_id"]
    with store_mod.connect(db) as conn:
        full = store_mod.get_finding_full(conn, result["finding_id"])
        assert len(full["triage_memories"]) == 1
        assert full["triage_memories"][0]["scope"] == "package"
        assert "not reachable" in full["triage_memories"][0]["reason"]


def test_mark_fp_scope_validation_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="triaged")
    result = srv.mark_fp_impl(finding_id, "fp", scope="everywhere",
                              db_path=db)
    assert result["error"] is not None
    assert "scope must be" in result["error"]
    result = srv.mark_fp_impl(finding_id, "", db_path=db)
    assert result["error"] is not None
    assert "reason is required" in result["error"]


# --- business impact -------------------------------------------------------


def test_business_impact_only_change_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="triaged")
        verification_id = store_mod.insert_verification(
            conn, finding_id, _reproduced_result()
        )
        assert verification_id
        finding, error = store_mod.update_business_impact(
            conn,
            finding_id,
            {
                "label": "Urgent",
                "affected_customers": "all users",
                "affected_services": "api",
                "affected_data": "sessions",
                "rationale": "auth bypass in prod",
            },
            "operator assessment",
            actor="operator",
        )
        assert error is None
        assert finding["business_impact"]["label"] == "Urgent"
        assert finding["severity"] == "high"
        assert finding["status"] == "triaged"
        full = store_mod.get_finding_full(conn, finding_id)
        assert len(full["verifications"]) == 1
        assert full["verifications"][0]["status"] == "reproduced"
        assert any(
            e["event"] == "business_impact_updated"
            for e in full["pipeline_events"]
        )
        _finding, error = store_mod.update_business_impact(
            conn, finding_id, {"label": "Severe"}, "bad label",
            actor="operator",
        )
        assert error is not None


# --- DB location -------------------------------------------------------------


def test_db_default_location_not_in_repo_mockllm(tmp_path):
    default = store_mod.default_db_path()
    assert default.name == "findings.db"
    assert default.parent.name == ".gmi-security-mcp"
    assert str(tmp_path) not in str(default)
    repo = tmp_path / "repo"
    repo.mkdir()
    assert not str(default).startswith(str(repo))


def test_db_explicit_path_warns_mockllm(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    explicit = str(repo / "findings.db")
    result = srv.list_findings_impl(db_path=explicit)
    assert result["error"] is None
    assert result["db_warning"] is not None
    assert "not committing" in result["db_warning"]
    assert Path(explicit).exists()
    default_result = srv.list_findings_impl(
        db_path=str(tmp_path / "other.db")
    )
    assert default_result["db_warning"] is not None


# --- store tools ------------------------------------------------------------


def test_list_findings_summaries_have_no_code_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        _insert_finding(conn, code="secret_code_here = 1")
        summaries, _cursor, total = store_mod.list_findings(conn)
    assert total == 1
    assert "code" not in summaries[0]
    assert summaries[0]["business_impact"]["label"] == "Not assessed"


def test_list_findings_pagination_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        for i in range(25):
            _insert_finding(
                conn, file="src/f%d.py" % i,
                code="query = x%d + user_input" % i,
            )
    with store_mod.connect(db) as conn:
        page1, cursor, total = store_mod.list_findings(conn, limit=20)
        assert total == 25
        assert len(page1) == 20
        assert cursor is not None
        page2, cursor2, _total = store_mod.list_findings(
            conn, limit=20, cursor=cursor
        )
        assert len(page2) == 5
        assert cursor2 is None
        ids = {f["id"] for f in page1} | {f["id"] for f in page2}
        assert len(ids) == 25


def test_get_finding_full_history_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="triaged")
        store_mod.insert_verdict(
            conn, finding_id, model=CHEAP, stage="stage1",
            verdict="real", severity="high", confidence=0.9,
        )
        store_mod.insert_verification(
            conn, finding_id, _reproduced_result()
        )
        full = store_mod.get_finding_full(conn, finding_id)
        assert full["code"] == "query = x + user_input"
        assert len(full["verdicts"]) == 1
        assert len(full["verifications"]) == 1
        assert len(full["pipeline_events"]) >= 1
        assert full["triage_memories"] == []
    missing = srv.get_finding_impl("fnd_nope", db_path=db)
    assert missing["finding"] is None
    assert "not found" in missing["error"]


def test_update_finding_refuses_skip_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="new")
    result = srv.update_finding_impl(
        finding_id, status="confirmed", reason="looks real",
        db_path=db,
    )
    assert result["error"] is not None
    assert "cannot move to confirmed" in result["error"]
    result = srv.update_finding_impl(
        finding_id, status="triaged", reason=None, db_path=db
    )
    assert result["error"] is not None
    assert "reason is required" in result["error"]


def test_mark_confirmed_refused_without_verification_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="verified")
    result = srv.mark_confirmed_impl(
        finding_id, "looks real", db_path=db
    )
    assert result["error"] is not None
    assert "LLM verdict alone cannot" in result["error"]
    assert "verify_finding" in result["error"]


def test_mark_confirmed_with_verification_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(conn, status="verified")
        store_mod.insert_verification(
            conn, finding_id, _reproduced_result()
        )
    result = srv.mark_confirmed_impl(
        finding_id, "oracle reproduced it", db_path=db
    )
    assert result["error"] is None
    assert result["finding"]["status"] == "confirmed"
    assert result["verification_id"] is not None


# --- wiring: triage, repo_scan, verify, disclosure ----------------------------


def test_triage_stores_finding_mockllm(tmp_path):
    db = _db(tmp_path)
    result = srv.triage_impl(
        finding="SQL injection in app",
        code="query = x + user_input",
        file="src/app.py",
        line=5,
        check="SQL injection",
        stage1_model=CHEAP,
        chat_fn=_mockllm_chat("real"),
        pricing=PRICING,
        db_path=db,
    )
    assert result["verdict"] == "real"
    assert result["finding_id"]
    assert result["db_warning"] is not None
    assert "not committing" in result["db_warning"]
    with store_mod.connect(db) as conn:
        full = store_mod.get_finding_full(conn, result["finding_id"])
        assert full["status"] == "triaged"
        assert len(full["verdicts"]) == 1
        assert full["verdicts"][0]["model"] == CHEAP


def test_triage_stores_redacted_code_mockllm(tmp_path):
    db = _db(tmp_path)
    result = srv.triage_impl(
        finding="Hardcoded secret",
        code='api_key = "sk-live-abcdefgh1234567890"',
        check="Hardcoded secrets",
        stage1_model=CHEAP,
        chat_fn=_mockllm_chat("real"),
        pricing=PRICING,
        db_path=db,
    )
    assert result["finding_id"]
    with store_mod.connect(db) as conn:
        full = store_mod.get_finding_full(conn, result["finding_id"])
        assert "sk-live-abcdefgh1234567890" not in full["code"]
        assert "[REDACTED]" in full["code"]
        # The evidence text is the finding plus the code, so it
        # must be redacted too, or the secret would reach the DB
        # through evidence_json even though the code is redacted.
        assert "sk-live-abcdefgh1234567890" not in json.dumps(
            full["evidence"]
        )


def test_triage_store_failure_keeps_verdict_mockllm(tmp_path):
    """Audit fix: sqlite3 errors are caught, so a broken store
    degrades to a store_error instead of losing the verdict."""
    broken_db = tmp_path / "not-a-db"
    broken_db.mkdir()
    result = srv.triage_impl(
        finding="SQL injection in app",
        code="query = x + user_input",
        check="SQL injection",
        stage1_model=CHEAP,
        chat_fn=_mockllm_chat("real"),
        pricing=PRICING,
        db_path=str(broken_db),
    )
    assert result["verdict"] == "real"
    assert result["finding_id"] is None
    assert result["store_error"] is not None
    assert "findings store failed" in result["store_error"]


def test_update_finding_refused_status_leaves_nothing_mockllm(tmp_path):
    """Audit fix: a refused status change in a combined call
    rolls the business-impact edit back too."""
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(
            conn, status="triaged", severity="critical"
        )
    result = srv.update_finding_impl(
        finding_id,
        business_impact={
            "label": "Urgent",
            "affected_customers": "all",
            "affected_services": "api",
            "affected_data": "credentials",
            "rationale": "auth bypass",
        },
        status="suppressed",
        reason="ignore it",
        db_path=db,
    )
    assert result["error"] is not None
    assert "disclosure-worthy" in result["error"]
    with store_mod.connect(db) as conn:
        stored = store_mod.get_finding(conn, finding_id)
        assert stored["status"] == "triaged"
        assert stored["business_impact"]["label"] == "Not assessed"


def test_repo_scan_stores_scan_and_findings_mockllm(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "server.js").write_text(
        "const p = path.join('/data', name);\n"
    )
    payload = {
        "version": "1.184.0",
        "results": [
            {
                "check_id": "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal",
                "path": "src/server.js",
                "start": {"line": 1},
                "extra": {
                    "message": "Path traversal via path.join",
                    "severity": "WARNING",
                },
            }
        ],
        "errors": [],
    }

    def _runner(cmd, timeout):
        return 0, json.dumps(payload), ""

    db = _db(tmp_path)
    result = srv.repo_scan_impl(
        repo_path=str(repo),
        stage1_model=CHEAP,
        stage2_model=QWEN,
        pricing=PRICING,
        semgrep_runner=_runner,
        chat_fn=_mockllm_chat("real"),
        db_path=db,
    )
    assert result["scan_id"]
    assert result["findings_total"] == 1
    assert result["findings"][0]["finding_id"]
    assert result["db_warning"] is not None
    assert "not committing" in result["db_warning"]
    with store_mod.connect(db) as conn:
        scan = store_mod.get_scan(conn, result["scan_id"])
        assert scan["status"] == "completed"
        assert scan["findings_total"] == 1
        summaries, _cursor, total = store_mod.list_findings(conn)
        assert total == 1
        assert summaries[0]["status"] == "triaged"


def test_repo_scan_dry_run_writes_nothing_mockllm(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "server.js").write_text("x = 1\n")
    db = _db(tmp_path)
    result = srv.repo_scan_impl(
        repo_path=str(repo),
        stage1_model=CHEAP,
        stage2_model=QWEN,
        pricing=PRICING,
        semgrep_runner=lambda cmd, timeout: (
            0,
            json.dumps({"results": [], "errors": []}),
            "",
        ),
        chat_fn=_mockllm_chat("real"),
        dry_run=True,
        db_path=db,
    )
    assert result["scan_id"] is None
    assert not Path(db).exists()


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    return repo


def test_verify_reads_writes_store_mockllm(tmp_path):
    db = _db(tmp_path)
    repo = _repo(tmp_path)
    triaged = srv.triage_impl(
        finding="SQL injection in app",
        code="query = x + user_input",
        check="SQL injection",
        stage1_model=CHEAP,
        chat_fn=_mockllm_chat("real"),
        pricing=PRICING,
        db_path=db,
    )
    finding_id = triaged["finding_id"]
    assert finding_id
    safe_poc = (
        "import json\n"
        "print(json.dumps({\"boolean_length_diff\": True,"
        " \"timing_delta_ms\": 800, \"sql_error\": False}))\n"
    )
    result = srv.verify_impl(
        finding=None,
        finding_id=finding_id,
        repo_path=str(repo),
        poc=safe_poc,
        run_poc=True,
        pricing=PRICING,
        db_path=db,
    )
    assert result["status"] == "reproduced"
    assert result["confirmed"] is True
    assert result["finding_id"] == finding_id
    assert result["verification_id"]
    with store_mod.connect(db) as conn:
        full = store_mod.get_finding_full(conn, finding_id)
        assert full["status"] == "verified"
        assert len(full["verifications"]) == 1
        assert full["verifications"][0]["status"] == "reproduced"
        assert len(full["verifications"][0]["artifacts"]) >= 1
    confirmed = srv.mark_confirmed_impl(
        finding_id, "oracle reproduced it", db_path=db
    )
    assert confirmed["error"] is None
    assert confirmed["finding"]["status"] == "confirmed"


def test_verify_finding_id_missing_in_store_mockllm(tmp_path):
    db = _db(tmp_path)
    repo = _repo(tmp_path)
    result = srv.verify_impl(
        finding=None,
        finding_id="fnd_missing",
        repo_path=str(repo),
        pricing=PRICING,
        db_path=db,
    )
    assert result["status"] == "error"
    assert "not found in the findings store" in result["error"]


def test_disclosure_refuses_unconfirmed_finding_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(
            conn, status="new", verdict="real", confidence=0.9
        )
    out = json.loads(
        srv.draft_private_disclosure(
            finding=_finding_dict(),
            repo="owner/repo",
            finding_id=finding_id,
            db_path=db,
        )
    )
    assert out["sent"] is False
    assert out["draft_markdown"] is None
    assert "status new" in out["error"]
    assert "confirmed" in out["error"]


def test_disclosure_allows_confirmed_finding_mockllm(tmp_path):
    db = _db(tmp_path)
    with store_mod.connect(db) as conn:
        finding_id, _ = _insert_finding(
            conn, status="confirmed", verdict="real", confidence=0.9,
            severity="high",
        )
    out = json.loads(
        srv.draft_private_disclosure(
            finding=_finding_dict(),
            repo="owner/repo",
            finding_id=finding_id,
            db_path=db,
        )
    )
    assert out["error"] is None
    assert out["sent"] is False
    assert out["draft_markdown"]


def test_disclosure_refuses_finding_not_in_store_mockllm(tmp_path):
    db = _db(tmp_path)
    out = json.loads(
        srv.draft_private_disclosure(
            finding=_finding_dict(),
            repo="owner/repo",
            finding_id="fnd_missing",
            db_path=db,
        )
    )
    assert out["sent"] is False
    assert "not in the findings store" in out["error"]


# --- dataset-v2 MockLLM floor ---------------------------------------------------


def test_dataset_v2_mockllm_floor(tmp_path):
    """Regression floor only: 56 findings through triage with a
    fixed MockLLM verdict, all stored. Never live, never reported
    as live accuracy."""
    data = json.loads((ROOT / "dataset-v2.json").read_text())
    findings = data["findings"]
    assert len(findings) == 56
    db = _db(tmp_path)
    stored = 0
    for item in findings:
        result = srv.triage_impl(
            finding="%s. %s" % (item["title"], item["explanation"]),
            code=item["code"],
            check=item.get("category"),
            stage1_model=CHEAP,
            chat_fn=_mockllm_chat("real", confidence=0.9),
            pricing=PRICING,
            db_path=db,
        )
        assert result["verdict"] == "real"
        assert result["finding_id"]
        stored += 1
    assert stored == 56
    listed = srv.list_findings_impl(limit=100, db_path=db)
    # S10 and F11 share identical code and check, so the store
    # deduplicates them into one finding, by design.
    assert listed["total"] == 55
    assert listed["error"] is None
    print(
        "mockllm dataset-v2 floor: stored %d/56 calls, %d unique "
        "findings (S10/F11 share identical code)" % (stored, 55)
    )


def test_validate_status_transition_mockllm():
    ok, _err = validate_mod.validate_status_transition(
        "new", "triaged"
    )
    assert ok is True
    ok, err = validate_mod.validate_status_transition(
        "new", "confirmed"
    )
    assert ok is False
    assert "LLM verdict alone" in err
    ok, err = validate_mod.validate_status_transition(
        "triaged", "confirmed", has_verification=True
    )
    assert ok is False
    assert "skip" in err
    ok, _err = validate_mod.validate_status_transition(
        "verified", "confirmed", has_verification=True
    )
    assert ok is True
    ok, _err = validate_mod.validate_status_transition(
        "suppressed", "triaged"
    )
    assert ok is True
    ok, _err = validate_mod.validate_status_transition(
        "false_positive", "verified"
    )
    assert ok is False


def test_verification_reproduced_two_of_three_signals_valid_mockllm():
    """A2 fix to an A1 latent rule: the SQLi oracle reproduces on
    2 of 3 signals, so a reproduced result with one failing
    assertion alongside passing ones must validate. A reproduced
    result with only failing assertions is still invalid."""
    result = _reproduced_result()
    result["assertions"] = [
        {"name": "boolean_length_diff", "passed": True, "detail": "yes"},
        {"name": "timing_delta", "passed": True, "detail": "800 ms"},
        {"name": "sql_error_signature", "passed": False, "detail": "no"},
    ]
    clean = validate_mod.norm_verification_result(result)
    assert clean is not None
    assert clean["confirmed"] is True
    result["assertions"] = [
        {"name": "a", "passed": False, "detail": "no"},
    ]
    assert validate_mod.norm_verification_result(result) is None
