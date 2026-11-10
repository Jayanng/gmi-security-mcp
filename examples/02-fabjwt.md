# Example 2: FAB Azure JWT, CVE-2026-59243, auth bypass

Expected verdict: real

Expected: REAL - critical. CVE-2026-59243, Flask-AppBuilder / apache-airflow-providers-fab before 3.7.3, published 29 Jul 2026. Fix: upgrade to 3.7.3, verify_signature defaults to True.

Check: Authentication and session flaws

```
CVE-2026-59243, Flask-AppBuilder / apache-airflow-providers-fab before 3.7.3, published 29 Jul 2026. CWE-347.
Code in flask_appbuilder/security/manager.py, _decode_and_validate_azure_jwt:

verify_signature = self.oauth_remotes["azure"].client_kwargs.get("verify_signature", False)
if verify_signature:
    keyset = JsonWebKey.import_key_set(self._get_microsoft_jwks())
    claims = authlib_jwt.decode(id_token, keyset)
    claims.validate()
    return claims
return jwt.decode(id_token, options={"verify_signature": False})

The Azure AD OAuth path decodes the ID token with verify_signature=False by default, so a forged or unsigned (alg:none) ID token presented to the OAuth callback authenticates as any user, including Admin. The Authentik path already defaulted to True. Fix: upgrade apache-airflow-providers-fab to 3.7.3, where verify_signature defaults to True.
```
