"""HOLDER (student): reveals only chosen facts and proves the credential is theirs."""

import json
import sys
import urllib.request
import urllib.error

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common import canon, sha256_hex, b64, unb64


def present(cred, disclosures, reveal, holder_priv, nonce, aud):
    """Reveal only the chosen attributes and sign the request."""
    shown = {k: disclosures[k] for k in reveal}  # selective disclosure

    msg = canon({"nonce": nonce, "aud": aud, "shown": sha256_hex(canon(shown))})

    return {
        "cred": cred,
        "shown": shown,
        "proof": {"nonce": nonce, "sig": b64(holder_priv.sign(msg))},
    }


def http(url, body=None):
    """Tiny JSON client; returns JSON even on an error status."""
    req = urllib.request.Request(
        url,
        json.dumps(body).encode() if body else None,
        {"Content-Type": "application/json"},
    )
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except json.JSONDecodeError:
            return {"ok": False, "result": f"HTTP {e.code} (non-JSON body)"}
    except urllib.error.URLError as e:
        return {"ok": False, "result": f"cannot reach verifier: {e.reason}"}


if __name__ == "__main__":
    server = "http://127.0.0.1:5000"
    reveal = sys.argv[1:] or ["age_over_18"]  # default: one fact

    cred = json.load(open("credential.json"))
    disc = json.load(open("disclosures.json"))
    key = Ed25519PrivateKey.from_private_bytes(unb64(open("holder_key.txt").read()))

    ch = http(server + "/challenge")  # 1. get nonce
    pres = present(cred, disc, reveal, key, ch["nonce"], ch["aud"])
    print(http(server + "/verify", pres))  # 2. send presentation
