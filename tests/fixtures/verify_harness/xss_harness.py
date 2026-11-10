"""Local XSS test harness for the verify_finding oracle.

Deliberately vulnerable, local only, stdlib only. render_page
reflects the query into a DOM sink: the value is assigned to
innerHTML inside a script block, so a unique token placed in the
query lands in an executable sink. render_page_safe escapes the
value first. There is no browser here, so the oracle accepts a
token captured in a DOM sink, not only a dialog capture.
"""

import html


def render_page(query):
    """Vulnerable: query reflected into an innerHTML sink."""
    return (
        "<html><body><div id=\"out\"></div>"
        "<script>document.getElementById('out').innerHTML = \""
        + query
        + "\";</script></body></html>"
    )


def render_page_safe(query):
    """Fixed: the value is escaped before it reaches the sink."""
    return (
        "<html><body><div id=\"out\"></div>"
        "<script>document.getElementById('out').innerHTML = \""
        + html.escape(query, quote=True)
        + "\";</script></body></html>"
    )
