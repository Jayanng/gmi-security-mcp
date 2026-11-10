# Example 9: Pickle deserialization RCE, CWE-502

Expected verdict: real

Expected: REAL - critical. Insecure deserialization, CWE-502, dataset finding S14. Fix: use json.loads, or signed / allowlisted data only.

Check: none, no clean mapping onto the 7 known checks

```
Semgrep finding, dataset S14, insecure deserialization, CWE-502.
Code in app.py:

import pickle
obj = pickle.loads(request.data)

request.data is untrusted, attacker-controlled bytes. Unpickling it can construct arbitrary Python objects and execute arbitrary code during deserialization. This is the same class as the Jackson-databind and Java deserialization flaws that have produced real CVEs. Fix: do not unpickle untrusted data. Use json.loads for plain data, or verify a signature and an allowlist before deserializing.
```
