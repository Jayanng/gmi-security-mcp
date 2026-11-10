# Example 3: Spring4Shell, CVE-2022-22965, RCE

Expected verdict: real

Expected: REAL - critical, only under the stated conditions. CVE-2022-22965, Spring Framework 5.3.0-5.3.17 / 5.2.0-5.2.19, JDK 9+, WAR on Tomcat, CVSS 9.8, disclosed 31 Mar 2022. Fix: upgrade to 5.3.18 / 5.2.20.

Check: none, no clean mapping onto the 7 known checks

```
CVE-2022-22965 (Spring4Shell), CVSS 9.8, Spring Framework 5.3.0-5.3.17 and 5.2.0-5.2.19, disclosed 31 Mar 2022.
Conditions for the known exploit path: Spring MVC or WebFlux, JDK 9 or higher, deployed as a WAR on Apache Tomcat. Spring Boot executable JARs are not affected by that path.
An attacker sends crafted HTTP parameters using data binding, for example class.module.classLoader.resources.context.parent.pipeline.first.pattern, to reach the Tomcat log handler, redirect the access log to a JSP file in the web root, and write a web shell. Fix: upgrade Spring Framework to 5.3.18 or 5.2.20, or Spring Boot to 2.6.6 or 2.5.12.
```
