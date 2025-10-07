#!/bin/bash
set -e

WALLET_FILE="ctf-wallet.json"

echo "=== Étape 1 : Création du wallet ($WALLET_FILE) ==="
solana-keygen new -o $WALLET_FILE --no-bip39-passphrase --force

echo
echo "=== Étape 2 : Récupération de la clé publique ==="
PUBKEY=$(solana-keygen pubkey $WALLET_FILE)
echo "Adresse publique : $PUBKEY"

echo
echo "=== Étape 3 : Configuration du cluster Devnet ==="
solana config set --url https://api.devnet.solana.com

echo
echo "=== Étape 4 : Airdrop de 2 SOL ==="
solana airdrop 2 $PUBKEY --url https://api.devnet.solana.com

echo
echo "=== Étape 5 : Vérification du solde ==="
solana balance $PUBKEY --url https://api.devnet.solana.com

echo
echo "=== ✅ Wallet test prêt à l'emploi ==="

