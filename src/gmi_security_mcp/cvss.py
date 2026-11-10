"""CVSS 3.1 base-score calculation from a vector string.

The OSV API returns severity as a vector string, for example
"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", with no numeric
score. This module computes the numeric base score from the vector
using the CVSS 3.1 specification, so explain_cve can report a real
score instead of inventing one.

CVSS 4.0 vectors are not scored here: the 4.0 formula is different
and this project does not implement it. A 4.0 vector is returned
as-is with score None.

Reference: FIRST CVSS v3.1 specification, base-score equations and
the Roundup definition (round up to one decimal place).
"""

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(value):
    """CVSS Roundup: smallest one-decimal number >= value.

    Implemented per the spec: work in units of 1e-5, and round up to
    the next tenth unless the value is already exact at that
    precision.
    """
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (math.floor(scaled / 10000) + 1) / 10


def cvss31_base_score(vector):
    """Numeric CVSS 3.1 base score for a vector string, or None.

    Returns None when the vector is not a CVSS 3.0/3.1 vector, when
    a metric is missing, or when a metric value is unknown.
    """
    if not vector or not isinstance(vector, str):
        return None
    text = vector.strip()
    if not (text.startswith("CVSS:3.0/") or text.startswith("CVSS:3.1/")):
        return None
    parts = {}
    for item in text.split("/")[1:]:
        if ":" not in item:
            return None
        key, value = item.split(":", 1)
        parts[key] = value
    needed = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(key not in parts for key in needed):
        return None
    try:
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        ui = _UI[parts["UI"]]
        c = _CIA[parts["C"]]
        i = _CIA[parts["I"]]
        a = _CIA[parts["A"]]
    except KeyError:
        return None
    scope_changed = parts["S"] == "C"
    if parts["S"] not in ("U", "C"):
        return None
    try:
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
    except KeyError:
        return None
    isc = 1 - (1 - c) * (1 - i) * (1 - a)
    if not scope_changed:
        impact = 6.42 * isc
        exploit = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        return _roundup(min(impact + exploit, 10))
    impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.029) ** 15)
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + exploit), 10))
