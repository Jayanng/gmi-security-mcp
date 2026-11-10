"""Deterministic SSRF PoC for the MockLLM floor and oracle tests.

Uses ssrf_harness in the same directory. Prints one JSON
evidence object as its last line. Stdlib only. The collector
runs on 127.0.0.1 only.
"""

import json
import uuid

import ssrf_harness

nonce = uuid.uuid4().hex[:16]
with ssrf_harness.Collector() as collector:
    ssrf_harness.vulnerable_fetch(collector.url + "?nonce=" + nonce)
    received = ""
    for path in collector.seen_paths:
        if nonce in path:
            received = nonce
            break
print(json.dumps({"nonce": nonce, "collector_received_nonce": received}))
