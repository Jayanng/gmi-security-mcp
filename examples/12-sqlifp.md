# Example 12: False positive, parameterised SQL

Expected verdict: false_positive

Expected: FALSE POSITIVE - low. Example 12 finding. Parameters are bound safely, so there is no SQL injection.

Check: SQL injection

```
Semgrep flagged: possible SQL injection, string formatting in query.
Code in reports/queries.py:

def orders_for_user(db, user_id):
    # user_id comes from the session, and the value is bound as a parameter
    return db.execute(
        "SELECT * FROM orders WHERE user_id = ?",
        (user_id,),
    ).fetchall()

The query uses a placeholder and the value is bound as a parameter by the database driver, so user input cannot break out of the query and inject SQL. Fix: none needed, this is a false positive.
```
