import os
import json
from pathlib import Path
import subprocess
import logging
import base64
import base58
import hmac
import time
import os
import hashlib
from solders.pubkey import Pubkey
from flask import Flask, request, jsonify
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import services.solana_service as flag
from config import FLAG_VISA, FLAG_BORDER

app = Flask(__name__)

SECRET = os.environ.get("CHALLENGE_SECRET", "La mer est agite").encode()
CHALLENGE_TTL = 120  # secondes
WALLET = os.getenv("OWNER_WALLET", "/root/mon_owner.json")
RPC_URL = os.getenv("RPC_URL", "https://api.devnet.solana.com")
CANDY_MACHINE_ID = os.getenv("CANDY_MACHINE_ID", "8HnVy3UeSJsqz4ZbuChiSgGrcTbeogJtrM9Fx3SFba8E")
COLLECTION_MINT = os.getenv("COLLECTION_MINT", "6Qo9R5KGboAANBLo5paZSbHK5rH2Yr2bFLLDw5dm9Tjr")
TOKEN_METADATA_PROGRAM_ID = Pubkey.from_string("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")

def get_metadata_pda(mint_str: str) -> str:
    mint = Pubkey.from_string(mint_str)
    (pda, _) = Pubkey.find_program_address(
        [b"metadata", bytes(TOKEN_METADATA_PROGRAM_ID), bytes(mint)],
        TOKEN_METADATA_PROGRAM_ID
    )
    return str(pda)

def make_challenge():
    challenge_bytes = os.urandom(16)
    challenge_b64 = base64.b64encode(challenge_bytes).decode()

    ts = str(int(time.time()))
    mac = hmac.new(SECRET, challenge_bytes + ts.encode(), hashlib.sha256).hexdigest()
    return challenge_b64, ts, mac

def verify_challenge(challenge_b64, ts, mac):
    try:
        challenge_bytes = base64.b64decode(challenge_b64, validate=True)
    except Exception:
        return None, False

    expected_mac = hmac.new(SECRET, challenge_bytes + ts.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, mac):
        return None, False

    if (int(time.time()) - int(ts)) > CHALLENGE_TTL:
        return None, False

    return challenge_bytes, True

@app.route("/get_challenge", methods=["POST"])
def get_challenge():
    challenge_b64, ts, mac = make_challenge()
    return jsonify({
        "challenge": challenge_b64,
        "ts": ts,
        "mac": mac
    })


WALLET_FILE = Path("minted_wallets.json")
minted_wallets = set()
if WALLET_FILE.exists():
    minted_wallets = set(json.loads(WALLET_FILE.read_text()))
else:
    minted_wallets = set()

def save_wallets():
    WALLET_FILE.write_text(json.dumps(list(minted_wallets)))



@app.route("/mint", methods=["POST"])
def mint_nft():
    data = request.get_json()
    participant_wallet = data.get("wallet")
    if not participant_wallet:
        return jsonify({"success": False, "error": "Missing wallet address"}), 400

    # 🔒 Vérification blacklist
    if participant_wallet in minted_wallets:
        return jsonify({"success": False, "error": "Wallet already minted"}), 400

    try:
        result = subprocess.check_output([
            "sugar", "mint",
            "-k", "/root/mon_owner.json",
            "--candy-machine", CANDY_MACHINE_ID,
            "--receiver", participant_wallet,
            "--rpc-url", RPC_URL
        ], stderr=subprocess.STDOUT)

        out = result.decode()
        mint_addr, tx_sig = None, None
        for line in out.splitlines():
            if line.strip().startswith("Mint:"):
                mint_addr = line.split("Mint:")[1].strip()

        # ✅ Ajouter à la blacklist après un mint réussi
        minted_wallets.add(participant_wallet)
        save_wallets()
        metadata_pda = get_metadata_pda(mint_addr)

        return jsonify({
            "success": True,
            "wallet": participant_wallet,
            "mint": mint_addr,
            "metadata": metadata_pda
        })

    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": e.output.decode()}), 500


@app.route("/submit_signature", methods=["POST"])
def submit_signature():
    data = request.get_json()
    pubkey = data.get("pubkey")
    signature_b64 = data.get("signature")
    challenge_b64 = data.get("challenge")
    ts = data.get("ts")
    mac = data.get("mac")

    if not pubkey or not signature_b64 or not challenge_b64 or not ts or not mac:
        return jsonify({"error": "Missing fields"}), 400

    challenge_bytes, ok = verify_challenge(challenge_b64, ts, mac)
    if not ok:
        return jsonify({"error": "Invalid or expired challenge"}), 400

    try:
        pubkey_bytes = base58.b58decode(pubkey)
        sig_bytes = base64.b64decode(signature_b64, validate=True)

        if len(pubkey_bytes) != 32:
            return jsonify({"error": "Invalid pubkey length"}), 400
        if len(sig_bytes) != 64:
            return jsonify({"error": "Invalid signature length"}), 400

        VerifyKey(pubkey_bytes).verify(challenge_bytes, sig_bytes)
        print(f"🔑 Pubkey reçu: {pubkey}")


        visa_ok, border_ok, border_exists = flag.verify_flags(pubkey)

        if visa_ok and border_ok:
            return jsonify({"status": "success", "flag": [FLAG_VISA, FLAG_BORDER]})
        elif visa_ok and not border_ok:
            return jsonify({"status": "success", "flag": FLAG_VISA})
        else:
            return jsonify({
                "status": "success",
                "flag": "You did not get any flag. Make sure you use the same public key."
            })

    except BadSignatureError:
        return jsonify({"error": "Verification failed"}), 400
    except Exception as e:
        app.logger.error("Erreur dans /submit_signature", exc_info=True)  # stacktrace complète dans les logs Docker
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)

