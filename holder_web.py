"""HOLDER web app: local UI + secrets stay on this machine."""

import json
import os

from flask import Flask, jsonify, render_template, request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common import unb64
from holder import present, http

VERIFIER = os.environ.get("VERIFIER_URL", "http://127.0.0.1:5000").rstrip("/")

app = Flask(__name__)

cred = json.load(open("credential.json"))
disc = json.load(open("disclosures.json"))
key = Ed25519PrivateKey.from_private_bytes(unb64(open("holder_key.txt").read()))


@app.get("/")
def index():
    return render_template("index.html", verifier=VERIFIER, attributes=list(disc.keys()))


@app.post("/api/prove")
def prove():
    reveal = (request.get_json(force=True, silent=True) or {}).get("reveal", [])
    if not reveal or any(r not in disc for r in reveal):
        return jsonify({"ok": False, "result": "pick at least one valid attribute"}), 400

    ch = http(VERIFIER + "/challenge")
    if "nonce" not in ch:
        return jsonify({"ok": False, "result": f"challenge failed: {ch}"}), 502

    pres = present(cred, disc, reveal, key, ch["nonce"], ch["aud"])
    return jsonify(http(VERIFIER + "/verify", pres))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
