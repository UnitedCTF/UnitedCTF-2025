import asyncio
import json
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solana.rpc.async_api import AsyncClient
from anchorpy import Provider, Wallet, Program, Idl, Context
from spl.token.instructions import get_associated_token_address

# === Constantes ===
RPC_URL = "https://api.devnet.solana.com"
PROGRAM_ID = Pubkey.from_string("FpaNQ2k5FehXLPpHjsAEYv1R3MS9d7iWTcGeYDx9z4sV")
PLAYER_WALLET_PATH = "../snippet_kit/setup/ctf-wallet.json"
IDL_PATH = "./idl.json"

# Données du NFT
NFT_MINT = Pubkey.from_string("")
METADATA_PDA = Pubkey.from_string("")

async def main():
    # Charger la keypair du joueur
    with open(PLAYER_WALLET_PATH, "r") as f:
        secret = json.load(f)
        player = Keypair.from_bytes(bytes(secret))
        wallet = Wallet(player)

    # Connexion RPC
    client = AsyncClient(RPC_URL)
    provider = Provider(client, wallet)

    # Charger IDL
    with open(IDL_PATH, "r") as f:
        data = json.load(f)
    idl = Idl.from_json(json.dumps(data))
    program = Program(idl, PROGRAM_ID, provider)

    # === Calcul des comptes nécessaires ===
    # ATA du joueur pour ce NFT
    token_account = get_associated_token_address(
        owner=player.pubkey(),
        mint=NFT_MINT,
    )

    # PDA visaData (seed = ["visa", user_pubkey])
    claim_record, _ = Pubkey.find_program_address(
        [b"claim", bytes(player.pubkey())],
        PROGRAM_ID,
    )

    print("👤 User:", player.pubkey())
    print("🪙 NFT Mint:", NFT_MINT)
    print("📑 Metadata PDA:", METADATA_PDA)
    print("💳 Token Account:", token_account)
    print("📂 claimRecord PDA:", claim_record)

    # === Envoi de la transaction claim ===
    try:
        tx_sig = await program.rpc["claim"](
            ctx=Context(
                accounts={
                    "user": player.pubkey(),
                    "nft_mint": NFT_MINT,
                    "metadata": METADATA_PDA,
                    "token_account": token_account,
                    "claim_record": claim_record,
                    "system_program": Pubkey.from_string("11111111111111111111111111111111"),
                    "token_program": Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
                },
                signers=[player],
            )
        )
        print("✅ Transaction envoyée:", tx_sig)
    except Exception as e:
        print("❌ Erreur lors de l'envoi:", e)

    await client.close()

if __name__ == "__main__":
    asyncio.run(main())

