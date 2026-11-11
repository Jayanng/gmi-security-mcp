# Example 11: False positive, XSS via textContent

Expected verdict: false_positive

Expected: FALSE POSITIVE - low. Example 11 finding. textContent does not parse HTML, so there is no XSS.

Check: Cross-site scripting (XSS)

```
Semgrep flagged: possible DOM XSS.
Code in profile.js:

el.textContent = userName

userName comes from the user, but it is assigned to textContent, not innerHTML. textContent treats the value as plain text and does not parse it as HTML or JavaScript, so no script can execute. Fix: none needed, this is a false positive. If the code used el.innerHTML = userName, that would be real DOM XSS.
```
