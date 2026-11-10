"""Deterministic SQLi PoC for the MockLLM floor and oracle tests.

Uses sqli_harness in the same directory. Prints one JSON
evidence object as its last line. Stdlib only.
"""

import json
import time

import sqli_harness

conn = sqli_harness.make_db()
true_rows = sqli_harness.vulnerable_query(conn, "1 AND 1=1")
false_rows = sqli_harness.vulnerable_query(conn, "1 AND 1=2")
boolean_diff = len(true_rows) != len(false_rows)

start = time.monotonic()
sqli_harness.vulnerable_query(
    conn, "1 AND (CASE WHEN 1=1 THEN sleep_ms(800) ELSE 0 END)"
)
slow_ms = (time.monotonic() - start) * 1000
start = time.monotonic()
sqli_harness.vulnerable_query(conn, "1")
fast_ms = (time.monotonic() - start) * 1000

sql_error = False
try:
    sqli_harness.vulnerable_query(conn, "'")
except Exception as err:
    lowered = str(err).lower()
    sql_error = any(
        word in lowered
        for word in ("syntax", "near", "unclosed", "unterminated",
                     "unrecognized token")
    )

print(json.dumps({
    "boolean_length_diff": boolean_diff,
    "timing_delta_ms": round(slow_ms - fast_ms, 1),
    "sql_error": sql_error,
}))
