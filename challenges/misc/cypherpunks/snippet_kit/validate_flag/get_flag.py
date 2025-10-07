#!/usr/bin/env python3
import sys
import base64
import json
import requests
import os
from solders.keypair import Keypair
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv(), override=False)  

SERVER = os.getenv("SERVER")

if not SERVER:
    sys.exit("Erreur: définis la variable d'environnement SERVER (snippet_kit/.env)")

wallet_path = os.getenv("WALLET_PATH", "../setup/ctf-wallet.json")

with open(wallet_path, "r") as f:
    secret = json.load(f)
keypair = Keypair.from_bytes(bytes(secret))

pubkey = str(keypair.pubkey())

resp = requests.post(f"{SERVER}/get_challenge", json={})
if resp.status_code != 200:
    print("Erreur get_challenge:", resp.text)
    exit(1)

challenge_data = resp.json()
challenge_b64 = challenge_data["challenge"]
ts = challenge_data["ts"]
mac = challenge_data["mac"]

print("[+] Challenge reçu :", challenge_b64)

challenge_bytes = base64.b64decode(challenge_b64)
signature = keypair.sign_message(challenge_bytes)
sig_b64 = base64.b64encode(bytes(signature)).decode()

print("[+] Signature générée :", sig_b64)

payload = {
    "pubkey": pubkey,
    "signature": sig_b64,
    "challenge": challenge_b64,
    "ts": ts,
    "mac": mac
}

resp2 = requests.post(f"{SERVER}/submit_signature", json=payload)
if resp2.status_code != 200:
    print("Erreur submit_signature:", resp2.text)
    exit(1)

print("[+] Réponse serveur :", resp2.json())

