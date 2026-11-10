# Example 4: MOVEit SQL injection, CVE-2023-34362

Expected verdict: real

Expected: REAL - critical. CVE-2023-34362, Progress MOVEit Transfer, CVSS 9.8, exploited May 2023 by Clop, 2,773 organisations. Fix: patch to 2021.0.6 / 2021.1.4 / 2022.0.4 / 2022.1.5 / 2023.0.1 or later.

Check: SQL injection

```
CVE-2023-34362, Progress MOVEit Transfer, CVSS 9.8, CISA KEV 2 Jun 2023. Mass-exploited from 27 May 2023 by the Clop group, about 2,773 organisations and 95 million people affected.
Finding: unauthenticated SQL injection in the MOVEit Transfer web application. An attacker sends crafted web requests, the injection pulls an administrator-level token from the database, then the application's own file-write feature is used to drop the LEMURLOOT web shell human2.aspx and steal stored files.
Representative vulnerable pattern, not MOVEit's proprietary source:

query = "SELECT token FROM sessions WHERE user = '" + username + "'"
cursor.execute(query)

Fix: patch MOVEit Transfer to 2021.0.6, 2021.1.4, 2022.0.4, 2022.1.5 or 2023.0.1 or later, and use parameterised queries.
```
