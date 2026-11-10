import os
from flask import request

@app.route("/read")
def read_file():
    name = os.path.basename(request.args.get("name"))
    with open(os.path.join("/data", name)) as handle:
        return handle.read()
