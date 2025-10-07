import asyncio, json
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from anchorpy import Provider, Program, Wallet, Idl
from solana.rpc.async_api import AsyncClient
import os

WALLET_PATH = os.getenv("WALLET_PATH", "../setup/ctf-wallet.json")
IDL_PATH = "..."
PROGRAM_ID = Pubkey.from_string(os.getenv("PROGRAM_ID", "FpaNQ2k5FehXLPpHjsAEYv1R3MS9d7iWTcGeYDx9z4sV")) # ne changez pas ceci

async def main():
    client = AsyncClient(os.getenv("RPC_URL", "https://api.devnet.solana.com"))

    with open(WALLET_PATH, "r") as f:
        secret = json.load(f)
    kp = Keypair.from_bytes(bytes(secret))
    wallet = Wallet(kp)

    provider = Provider(client, wallet)

    with open(IDL_PATH, "r") as f:
        data = json.load(f)
    idl = Idl.from_json(json.dumps(data))
    program = Program(idl, PROGRAM_ID, provider)

    signer_pubkey = wallet.payer.pubkey()
    claim_record_pda, _ = Pubkey.find_program_address(
        [b"claim", bytes(signer_pubkey)],
        PROGRAM_ID
    )
    border_record_pda, _ = Pubkey.find_program_address(
        [b"border", bytes(signer_pubkey)],
        PROGRAM_ID
    )

    print(f"👤 Signer: {signer_pubkey}")
    print(f"📌 ClaimRecord PDA: {claim_record_pda}")
    print(f"📌 BorderRecord PDA: {border_record_pda}")

    try:
        claim_record = await program.account["ClaimRecord"].fetch(claim_record_pda)
        print("📜 ClaimRecord:", claim_record)
    except Exception as e:
        print("⚠️ ClaimRecord introuvable:", e)

    try:
        border_record = await program.account["BorderRecord"].fetch(border_record_pda)
        print("🛂 BorderRecord:", border_record)
    except Exception as e:
        print("⚠️ BorderRecord introuvable:", e)

    await client.close()

if __name__ == "__main__":
    asyncio.run(main())

