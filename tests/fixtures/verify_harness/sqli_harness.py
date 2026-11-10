"""Local SQLi test harness for the verify_finding oracle.

Deliberately vulnerable, local only, stdlib only. Used by the
Phase A1 oracle tests and live runs. Do NOT deploy this: the
vulnerable_query function builds SQL with string formatting on
purpose, so a PoC can demonstrate boolean, timing, and error
signals against it. safe_query shows the parameterised form.

Timing signal: a SQL function named sleep_ms is registered, so a
payload can make the query sleep only when a condition is true.
"""

import sqlite3
import time


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.create_function("sleep_ms", 1, lambda ms: time.sleep(ms / 1000.0))
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice')")
    conn.execute("INSERT INTO users VALUES (2, 'bob')")
    conn.commit()
    return conn


def vulnerable_query(conn, user_input):
    """Vulnerable: user input is formatted straight into the SQL."""
    cursor = conn.execute(
        "SELECT name FROM users WHERE id = %s" % user_input
    )
    return [row[0] for row in cursor.fetchall()]


def safe_query(conn, user_input):
    """Fixed: parameterised query, input never becomes SQL."""
    cursor = conn.execute(
        "SELECT name FROM users WHERE id = ?", (user_input,)
    )
    return [row[0] for row in cursor.fetchall()]
