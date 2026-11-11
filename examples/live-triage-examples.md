# Live Triage examples - 12 real examples

1. 1 - Log4Shell, CVE-2021-44228, Log4j JNDI RCE - REAL - critical. CVE-2021-44228, Log4j 2.0-beta9 to 2.14.1, CVSS 10.0, disclosed 10 Dec 2021. Fix: upgrade to Log4j 2.17.1 or later.
2. 2 - FAB Azure JWT, CVE-2026-59243, auth bypass - REAL - critical. CVE-2026-59243, Flask-AppBuilder / apache-airflow-providers-fab before 3.7.3, published 29 Jul 2026. Fix: upgrade to 3.7.3, verify_signature defaults to True.
3. 3 - Spring4Shell, CVE-2022-22965, RCE - REAL - critical, only under the stated conditions. CVE-2022-22965, Spring Framework 5.3.0-5.3.17 / 5.2.0-5.2.19, JDK 9+, WAR on Tomcat, CVSS 9.8, disclosed 31 Mar 2022. Fix: upgrade to 5.3.18 / 5.2.20.
4. 4 - MOVEit SQL injection, CVE-2023-34362 - REAL - critical. CVE-2023-34362, Progress MOVEit Transfer, CVSS 9.8, exploited May 2023 by Clop, 2,773 organisations. Fix: patch to 2021.0.6 / 2021.1.4 / 2022.0.4 / 2022.1.5 / 2023.0.1 or later.
5. 5 - Apache path traversal, CVE-2021-41773 - REAL - high, critical with CGI. CVE-2021-41773, Apache HTTP Server 2.4.49, CISA KEV, fix 2.4.51 (2.4.50 fix was incomplete, CVE-2021-42013).
6. 6 - Struts2 OGNL, CVE-2017-5638, Equifax - REAL - critical. CVE-2017-5638, Apache Struts2 2.3.5-2.3.31 / 2.5-2.5.10, CVSS 10.0, S2-045, Mar 2017, Equifax breach, 147 million people. Fix: 2.3.32 / 2.5.10.1.
7. 7 - PAN-OS command injection, CVE-2024-3400 - REAL - critical. CVE-2024-3400, Palo Alto PAN-OS 10.2 / 11.0 / 11.1 GlobalProtect, CVSS 10.0, Apr 2024, Operation MidnightEclipse, CISA KEV. Fix: 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3.
8. 8 - XZ supply chain, CVE-2024-3094, OSV finding - REAL - critical. CVE-2024-3094, XZ Utils 5.6.0 / 5.6.1, CVSS 10.0, disclosed 29 Mar 2024 by Andres Freund. Fix: downgrade to 5.4.6 or upgrade to 5.6.2.
9. 9 - Pickle deserialization RCE, CWE-502 - REAL - critical. Insecure deserialization, CWE-502, example 9 finding. Fix: use json.loads, or signed / allowlisted data only.
10. 10 - False positive, SSRF allowlisted host - FALSE POSITIVE - low. Example 10 finding. A fixed URL is not user-controlled, so there is no SSRF.
11. 11 - False positive, XSS via textContent - FALSE POSITIVE - low. Example 11 finding. textContent does not parse HTML, so there is no XSS.
12. 12 - False positive, parameterised SQL - FALSE POSITIVE - low. Example 12 finding. Parameters are bound safely, so there is no SQL injection.

Verified live 2026-11-09: CVE-2021-44228, CVE-2026-59243, CVE-2022-22965, CVE-2023-34362, CVE-2021-41773, CVE-2017-5638, CVE-2024-3400, CVE-2024-3094. Examples 9 to 12 are the four non-CVE examples, written from representative code.
Representative code is labelled as such where the vendor source is proprietary (MOVEit, PAN-OS); the FAB code is from the Flask-AppBuilder docs, and the other CVE entries give the real product, versions, dates and fix.
