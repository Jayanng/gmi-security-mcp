import requests
from flask import request

def validate_url(raw):
    parsed = urlparse(raw)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return raw

@app.route("/proxy")
def proxy():
    url = validate_url(request.args.get("url"))
    response = requests.get(url)
    return response.text
