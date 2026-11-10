from flask import request

def get_user(cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
