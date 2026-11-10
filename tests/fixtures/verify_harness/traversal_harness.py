"""Local path traversal test harness for the verify_finding oracle.

Deliberately vulnerable, local only, stdlib only. vulnerable_read
joins a user-supplied path onto a base directory with no check,
so ../ segments escape the base. The PoC targets /etc/passwd, a
public system file, and the oracle looks for its root-entry
signature in the returned content.
"""

import os


def vulnerable_read(base_dir, user_path):
    """Vulnerable: user path joined onto the base, no check."""
    path = os.path.join(base_dir, user_path)
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def safe_read(base_dir, user_path):
    """Fixed: the resolved path must stay inside the base dir."""
    base = os.path.realpath(base_dir)
    path = os.path.realpath(os.path.join(base, user_path))
    if path != base and not path.startswith(base + os.sep):
        raise ValueError("path escapes the base directory")
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()
