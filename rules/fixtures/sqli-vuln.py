from flask import request

def get_user(cursor):
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    cursor.execute(query)
    return cursor.fetchone()
