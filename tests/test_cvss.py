"""Unit tests for CVSS 3.1 base-score calculation.

No API calls. Vectors are well-known published scores.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import cvss


def test_log4shell_vector_is_10():
    assert (
        cvss.cvss31_base_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        )
        == 10.0
    )


def test_deepmerge_vector_is_5_3():
    assert (
        cvss.cvss31_base_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
        )
        == 5.3
    )


def test_classic_9_8_vector():
    assert (
        cvss.cvss31_base_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        == 9.8
    )


def test_all_none_is_zero():
    assert (
        cvss.cvss31_base_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        )
        == 0.0
    )


def test_cvss4_vector_returns_none():
    assert (
        cvss.cvss31_base_score(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N"
        )
        is None
    )


def test_malformed_vectors_return_none():
    assert cvss.cvss31_base_score("") is None
    assert cvss.cvss31_base_score(None) is None
    assert cvss.cvss31_base_score("CVSS:3.1/AV:N/AC:L") is None
    assert (
        cvss.cvss31_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        is None
    )
    assert cvss.cvss31_base_score("not a vector") is None
