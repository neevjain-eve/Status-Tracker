"""
Refreshes the Microsoft Graph OneDrive access token used by Manager Task Tracker,
independent of any browser being open, and relays it into od_config.json.

Runs on a GitHub Actions schedule. Uses a confidential-client (client secret)
refresh_token grant, which is NOT subject to the 24-hour hard cap that
single-page-app (public client) refresh tokens get -- it rolls forward
indefinitely as long as this workflow keeps running on schedule.

Each run:
  1. Exchanges the stored refresh_token for a new access_token + a NEW refresh_token
     (Azure AD rotates it on every use).
  2. Obfuscates the access_token the same way the app's own JS does (XOR each byte
     with 73, hex-encode) so the existing browser-side _deobfTok() keeps working
     unmodified.
  3. Merges {masterToken, masterTokenTime} into od_config.json and commits it.
  4. Updates the MS_REFRESH_TOKEN GitHub Actions secret to the newly rotated value,
     so the next scheduled run keeps working.
"""
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

from nacl import encoding, public

CLIENT_ID = os.environ["MS_CLIENT_ID"]
CLIENT_SECRET = os.environ["MS_CLIENT_SECRET"]
TENANT_ID = os.environ["MS_TENANT_ID"]
REFRESH_TOKEN = os.environ["MS_REFRESH_TOKEN"]
GH_SECRETS_PAT = os.environ["GH_SECRETS_PAT"]
REPO = os.environ.get("GITHUB_REPOSITORY", "neevjain-eve/Status-Tracker")
CONFIG_PATH = os.environ.get("OD_CONFIG_PATH", "od_config.json")

TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
API = f"https://api.github.com/repos/{REPO}"


def obf_token(token: str) -> str:
    # Matches the app's own _obfTok(): XOR each char code with 73, hex-pad to 2.
    return "".join(f"{(ord(c) ^ 73):02x}" for c in token)


def refresh_ms_token():
    import urllib.parse as up

    body = up.urlencode(
        {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": REFRESH_TOKEN,
            "grant_type": "refresh_token",
            "scope": "offline_access Files.ReadWrite",
        }
    ).encode()
    req = urllib.request.Request(
        TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print("Token refresh failed:", e.code, e.read().decode(), file=sys.stderr)
        raise


def gh_request(url, method="GET", data=None, token=GH_SECRETS_PAT):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "StatusTracker-token-refresh",
    }
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def update_refresh_token_secret(new_refresh_token: str):
    status, pubkey_resp = gh_request(f"{API}/actions/secrets/public-key")
    if status != 200:
        print("Could not fetch secrets public key:", status, pubkey_resp, file=sys.stderr)
        return False
    key_id = pubkey_resp["key_id"]
    public_key = public.PublicKey(pubkey_resp["key"].encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = base64.b64encode(sealed_box.encrypt(new_refresh_token.encode("utf-8"))).decode("utf-8")
    status, resp = gh_request(
        f"{API}/actions/secrets/MS_REFRESH_TOKEN",
        method="PUT",
        data={"encrypted_value": encrypted, "key_id": key_id},
    )
    if status not in (201, 204):
        print("Could not update MS_REFRESH_TOKEN secret:", status, resp, file=sys.stderr)
        return False
    return True


def main():
    tokens = refresh_ms_token()
    access_token = tokens["access_token"]
    new_refresh_token = tokens["refresh_token"]

    with open(CONFIG_PATH) as f:
        cfg = json.load(f)

    import time

    cfg["masterToken"] = obf_token(access_token)
    cfg["masterTokenTime"] = int(time.time() * 1000)

    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f)

    ok = update_refresh_token_secret(new_refresh_token)
    if not ok:
        print("WARNING: refresh token secret was not rotated; next run may fail.", file=sys.stderr)

    subprocess.run(["git", "config", "user.email", "actions@github.com"], check=True)
    subprocess.run(["git", "config", "user.name", "OneDrive Token Refresh Bot"], check=True)
    subprocess.run(["git", "add", CONFIG_PATH], check=True)
    diff = subprocess.run(["git", "diff", "--cached", "--quiet"])
    if diff.returncode == 0:
        print("No changes to commit (unexpected, token should always change).")
        return
    subprocess.run(
        ["git", "commit", "-m", "auto: refresh OneDrive token (scheduled, no browser) [skip ci]"],
        check=True,
    )
    subprocess.run(["git", "push"], check=True)
    print("Token refreshed and relayed successfully.")


if __name__ == "__main__":
    main()
