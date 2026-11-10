# Example 6: Struts2 OGNL, CVE-2017-5638, Equifax

Expected verdict: real

Expected: REAL - critical. CVE-2017-5638, Apache Struts2 2.3.5-2.3.31 / 2.5-2.5.10, CVSS 10.0, S2-045, Mar 2017, Equifax breach, 147 million people. Fix: 2.3.32 / 2.5.10.1.

Check: none, no clean mapping onto the 7 known checks

```
CVE-2017-5638, Apache Struts2, CVSS 10.0, advisory S2-045, Mar 2017. Used in the Equifax breach, about 147 million people affected.
The Jakarta Multipart parser puts a raw Content-Type header value into an error message that is then evaluated as an OGNL expression. An unauthenticated attacker sends a crafted Content-Type header containing %{...} OGNL, Struts2 evaluates it, and the attacker runs an arbitrary OS command, for example via ProcessBuilder, with output returned in the response.
Affected: Struts 2.3.5-2.3.31 and 2.5-2.5.10. Fix: upgrade to 2.3.32 or 2.5.10.1.
```
