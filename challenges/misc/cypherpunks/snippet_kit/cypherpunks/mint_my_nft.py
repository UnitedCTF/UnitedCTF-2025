#!/usr/bin/env python3
import sys, os, json, requests
from solders.keypair import Keypair
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv(), override=False)

SERVER = os.getenv("SERVER")
if not SERVER:
    sys.exit("Erreur: définis la variable d'environnement SERVER (dans .env)")

wallet_path = os.getenv("WALLET_PATH", "../setup/ctf-wallet.json")

with open(wallet_path, "r") as f:
    secret = json.load(f)
keypair = Keypair.from_bytes(bytes(secret))
pubkey = str(keypair.pubkey())

print("[+] Wallet chargé :", pubkey)

resp = requests.post(f"{SERVER}/mint", json={"wallet": pubkey})
if resp.status_code != 200:
    sys.exit("Erreur /mint: " + resp.text)

data = resp.json()
if data.get("success"):
    print("[+] Mint réussi !")
    print("    Mint :", data.get("mint"))
    print("   Metadata  :", data.get("metadata"))
else:
    print("❌ Mint échoué :", data.get("error"))

