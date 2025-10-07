import asyncio
from solders.pubkey import Pubkey
from solana.rpc.async_api import AsyncClient
from anchorpy import Program, Provider, Wallet, Idl
from anchorpy.error import AccountDoesNotExistError
import logging

logger = logging.getLogger("visa_ctf")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

RPC_URL = "https://api.devnet.solana.com"
PROGRAM_ID_STR = "FpaNQ2k5FehXLPpHjsAEYv1R3MS9d7iWTcGeYDx9z4sV"
IDL_PATH = "./idl.json"

logging.basicConfig(level=logging.WARN)

program_id = Pubkey.from_string(PROGRAM_ID_STR)

with open(IDL_PATH, "r") as f:
    idl = Idl.from_json(f.read())

client = AsyncClient(RPC_URL, commitment="finalized")
provider = Provider(client, Wallet.dummy())
program = Program(idl, program_id, provider)


async def _verify_flags_async(user_pubkey_b58: str) -> tuple[bool, bool, bool]:
    """
    Retourne (visa_ok, border_ok, border_exists)
    - visa_ok: joueur a claim (claim_record.has_claimed == True)
    - border_ok: joueur a traversé (border_record.has_crossed == True)
    - border_exists: le PDA border_record a déjà été créé
    """
    visa_ok = False
    border_ok = False
    border_exists = False

    user_pubkey = Pubkey.from_string(user_pubkey_b58)

    # --- Visa (ClaimRecord) ---
    try:
        claim_pda, _ = Pubkey.find_program_address(
            [b"claim", bytes(user_pubkey)],
            program.program_id
        )
        claim_record = await program.account["ClaimRecord"].fetch(claim_pda)
        visa_ok = bool(claim_record.has_claimed)
    except Exception as e:
        visa_ok = False
        print(f"[VISA] Impossible de fetch ClaimRecord pour {user_pubkey_b58}: {e}")

    # --- Border (BorderRecord) ---
    try:
        border_pda, _ = Pubkey.find_program_address(
            [b"border", bytes(user_pubkey)],
            program.program_id
        )
        border_record = await program.account["BorderRecord"].fetch(border_pda)
        border_ok = bool(border_record.has_crossed)
        border_exists = True
    except Exception as e:
        border_ok = False
        border_exists = False
        print(f"[BORDER] Impossible de fetch BorderRecord pour {user_pubkey_b58}: {e}")

    return visa_ok, border_ok, border_exists


def verify_flags(user_pubkey_b58: str) -> tuple[bool, bool, bool]:
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(_verify_flags_async(user_pubkey_b58))
