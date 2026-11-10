# Example 7: PAN-OS command injection, CVE-2024-3400

Expected verdict: real

Expected: REAL - critical. CVE-2024-3400, Palo Alto PAN-OS 10.2 / 11.0 / 11.1 GlobalProtect, CVSS 10.0, Apr 2024, Operation MidnightEclipse, CISA KEV. Fix: 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3.

Check: none, no clean mapping onto the 7 known checks

```
CVE-2024-3400, Palo Alto Networks PAN-OS GlobalProtect, CVSS 10.0, published 12 Apr 2024, CISA KEV the same day, exploited in Operation MidnightEclipse.
An unauthenticated attacker sends a crafted request to the GlobalProtect gateway or portal that creates an arbitrary file, which is then used to execute commands with root privileges on the firewall. Affected: PAN-OS 10.2.0-10.2.9, 11.0.0-11.0.4, 11.1.0-11.1.2 with GlobalProtect enabled. Cloud NGFW, Panorama and Prisma Access are not affected.
Representative vulnerable pattern, not Palo Alto's proprietary code:

os.system("telemetry-upload " + request.args["device"])

Fix: apply hotfix 10.2.9-h1, 11.0.4-h1 or 11.1.2-h3 or later.
```
