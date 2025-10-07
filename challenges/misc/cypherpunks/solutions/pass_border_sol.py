import asyncio
import json
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from anchorpy import Provider, Program, Context, Idl, Wallet
from solana.rpc.async_api import AsyncClient

WALLET_PATH = "../snippet_kit/setup/ctf-wallet.json"
IDL_PATH = "./idl.json"
PROGRAM_ID = Pubkey.from_string("FpaNQ2k5FehXLPpHjsAEYv1R3MS9d7iWTcGeYDx9z4sV")

CHOSEN_GATE = 158     
BRIBE_AMOUNT = 15_000  # voir transaction sur la blockchain

async def main():
    try:
        client = AsyncClient("https://api.devnet.solana.com")

        # Charger le wallet
        with open(WALLET_PATH, "r") as f:
            secret = json.load(f)
        kp = Keypair.from_bytes(bytes(secret))
        wallet = Wallet(kp)
        print(f"👤 Signer: {wallet.payer.pubkey()}")

        provider = Provider(client, wallet)

        # Charger l’IDL
        with open(IDL_PATH, "r") as f:
            data = json.load(f)
        idl = Idl.from_json(json.dumps(data))
        program = Program(idl, PROGRAM_ID, provider)

        # === Calcul des PDA ===
        claim_record_pda, _ = Pubkey.find_program_address(
            [b"claim", bytes(wallet.payer.pubkey())],
            PROGRAM_ID,
        )
        border_record_pda, _ = Pubkey.find_program_address(
            [b"border", bytes(wallet.payer.pubkey())],
            PROGRAM_ID,
        )
        print(f"📌 ClaimRecord PDA: {claim_record_pda}")
        print(f"📌 BorderRecord PDA: {border_record_pda}")
        print("Méthodes disponibles dans l’IDL :")
        for ix in program.idl.instructions:
            print(" -", ix.name)


        # === Appel crossBorder ===
        try:
            ctx = Context(
                accounts={
                    "signer": wallet.payer.pubkey(),
                    "claim_record": claim_record_pda,
                    "border_record": border_record_pda,
                    "system_program": Pubkey.from_string("11111111111111111111111111111111"),
                },
                signers=[wallet.payer],
            )

            tx = await program.rpc["cross_border"](CHOSEN_GATE, BRIBE_AMOUNT, ctx=ctx)
            print(f"✅ Transaction envoyée: {tx}")

        except Exception as e:
            print(f"❌ Erreur lors de l’appel à crossBorder: {e}")
            return


        await client.close()

    except Exception as e:
        print(f"💥 Erreur fatale: {e}")

if __name__ == "__main__":
    asyncio.run(main())

