import requests
from flask import request

@app.route("/proxy")
def proxy():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text
