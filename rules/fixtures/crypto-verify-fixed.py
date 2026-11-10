import jwt

def verify_token(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])
