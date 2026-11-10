import jwt

def decode_token(token):
    return jwt.decode(token, options={"verify_signature": False})

def decode_legacy(token):
    return jwt.decode(token, verify=False)
