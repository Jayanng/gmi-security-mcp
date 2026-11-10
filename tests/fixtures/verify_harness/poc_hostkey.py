"""Deterministic host-key PoC for the MockLLM floor and oracle tests.

Uses hostkey_harness in the same directory. Prints one JSON
evidence object as its last line. Paramiko only. The test SSH
server runs on 127.0.0.1 with a fresh host key; the PoC connects
with no host key verification and measures the mismatch: the
fingerprint it actually saw against the fingerprint of a freshly
generated decoy key, both in the same colon-hex format, so the
connection succeeded with a wrong, unverified host key.
The evidence carries both fingerprints: the oracle requires
them, a bare mismatch boolean is not a measurement.
"""

import json

import paramiko

import hostkey_harness

port, server_key, stop = hostkey_harness.start_test_server()
try:
    decoy = paramiko.RSAKey.generate(2048)
    decoy_fp = ":".join("%02x" % b for b in decoy.get_fingerprint())
    connected, seen_fp = hostkey_harness.connect_no_verify(port)
    print(json.dumps({
        "connected": connected,
        "host_key_verified": False,
        "host_key_mismatch": connected and seen_fp != decoy_fp,
        "seen_fingerprint": seen_fp,
        "expected_fingerprint": decoy_fp,
    }))
finally:
    stop()
