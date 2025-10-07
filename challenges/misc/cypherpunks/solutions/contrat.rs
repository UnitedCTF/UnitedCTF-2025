use anchor_lang::prelude::*;
use anchor_spl::token::TokenAccount;
use std::str::FromStr;

declare_id!("2R2CMh6xqqS6Fe69pmTnaSsivSd2HSf4JKM7XGWNe8QN");

// === Paramètres ===
pub const TOKEN_METADATA_PROGRAM_ID: &str =
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
pub const COLLECTION_MINT: &str =
    "6Qo9R5KGboAANBLo5paZSbHK5rH2Yr2bFLLDw5dm9Tjr";

// === Config jeu ===
pub const SECRET_GATE: u8 = 158;
pub const BRIBE_AMOUNT: u64 = 15_000;

#[program]
pub mod cypherpunks {
    use super::*;

    /// Le joueur prouve on-chain qu'il détient le NFT -> on délivre son visa
    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let user = ctx.accounts.user.key();
        let nft_mint = ctx.accounts.nft_mint.key();
        let metadata = ctx.accounts.metadata.key();

        // Vérifier PDA metadata (Metaplex)
        let token_metadata_program = Pubkey::from_str(TOKEN_METADATA_PROGRAM_ID).unwrap();
        let (expected_meta, _) = Pubkey::find_program_address(
            &[b"metadata", token_metadata_program.as_ref(), nft_mint.as_ref()],
            &token_metadata_program,
        );
        require_keys_eq!(expected_meta, metadata, ErrorCode::InvalidMetadataPda);

        // Vérifier ATA
        let ata = &ctx.accounts.token_account;
        require_keys_eq!(ata.owner, user, ErrorCode::TokenAccountOwnerMismatch);
        require_keys_eq!(ata.mint, nft_mint, ErrorCode::TokenAccountMintMismatch);
        require!(ata.amount >= 1, ErrorCode::EmptyTokenAccount);

        // Vérifier que le NFT appartient à la collection
        let data = ctx.accounts.metadata.try_borrow_data()?;

        // On cherche simplement la clé de la collection dans les bytes du metadata
        let coll = Pubkey::from_str(COLLECTION_MINT).unwrap();
        require!(
            data.windows(32).any(|w| w == coll.as_ref()),
            ErrorCode::NotInCollection
        );

        // Init/maj du ClaimRecord
        let claim_record = &mut ctx.accounts.claim_record;
        require!(!claim_record.has_claimed, ErrorCode::AlreadyHasVisa);
        claim_record.has_claimed = true;
        claim_record.ts = Clock::get()?.unix_timestamp;
        claim_record.player = user;

        emit!(VisaIssued {
            player: user,
            ts: claim_record.ts,
        });

        msg!("✅ Visa délivré à {}", user);
        Ok(())
    }

    /// Passage frontière : nécessite un visa valide
    pub fn cross_border(
        ctx: Context<CrossBorder>,
        chosen_gate: u8,
        bribe: u64,
    ) -> Result<()> {
        let user = ctx.accounts.signer.key();
        let claim_record = &ctx.accounts.claim_record;
        let border_record = &mut ctx.accounts.border_record;

        require!(claim_record.has_claimed, ErrorCode::VisaMissingOrInvalid);
        require!(!border_record.has_crossed, ErrorCode::AlreadyCrossed);
        require!(bribe >= BRIBE_AMOUNT, ErrorCode::BribeTooLow);

        border_record.attempts = border_record
            .attempts
            .checked_add(1)
            .ok_or(ErrorCode::Overflow)?;

        let now = Clock::get()?.unix_timestamp;

        if chosen_gate == SECRET_GATE {
            border_record.has_crossed = true;
            border_record.ts = now;
            border_record.player = user;

            emit!(BorderCrossed {
                player: user,
                issued_at: now,
            });

            msg!("🚪 {} a franchi la frontière !", user);
        } else {
            return err!(ErrorCode::WrongGate);
        }

        Ok(())
    }
}


#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    /// Mint du NFT
    /// CHECK: validé via PDA metadata
    pub nft_mint: UncheckedAccount<'info>,

    /// PDA metadata
    /// CHECK: vérifié en code
    pub metadata: UncheckedAccount<'info>,

    /// ATA du joueur
    pub token_account: Account<'info, TokenAccount>,

    /// ClaimRecord lié à ce joueur
    #[account(
        init_if_needed,
        payer = user,
        seeds = [b"claim", user.key().as_ref()],
        bump,
        space = 8 + ClaimRecord::SIZE
    )]
    pub claim_record: Account<'info, ClaimRecord>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, anchor_spl::token::Token>,
}

#[derive(Accounts)]
pub struct CrossBorder<'info> {
    #[account(mut, signer)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"claim", signer.key().as_ref()],
        bump,
        constraint = claim_record.has_claimed @ ErrorCode::VisaMissingOrInvalid
    )]
    pub claim_record: Account<'info, ClaimRecord>,

    #[account(
        init,
        payer = signer,
        seeds = [b"border", signer.key().as_ref()],
        bump,
        space = 8 + BorderRecord::SIZE
    )]
    pub border_record: Account<'info, BorderRecord>,

    pub system_program: Program<'info, System>,
}


#[account]
pub struct ClaimRecord {
    pub has_claimed: bool,
    pub ts: i64,
    pub player: Pubkey,
}
impl ClaimRecord {
    pub const SIZE: usize = 1 + 8 + 32;
}

#[account]
pub struct BorderRecord {
    pub has_crossed: bool,
    pub attempts: u8,
    pub ts: i64,
    pub player: Pubkey,
}
impl BorderRecord {
    pub const SIZE: usize = 1 + 1 + 8 + 32; // = 42, arrondi
}


#[event]
pub struct VisaIssued {
    pub player: Pubkey,
    pub ts: i64,
}
#[event]
pub struct BorderCrossed {
    pub player: Pubkey,
    pub issued_at: i64,
}


#[error_code]
pub enum ErrorCode {
    #[msg("Invalid metadata PDA")]
    InvalidMetadataPda,
    #[msg("Invalid ATA owner")]
    TokenAccountOwnerMismatch,
    #[msg("Invalid ATA mint")]
    TokenAccountMintMismatch,
    #[msg("Empty ATA")]
    EmptyTokenAccount,
    #[msg("NFT not part of the collection")]
    NotInCollection,
    #[msg("Visa missing or invalid")]
    VisaMissingOrInvalid,
    #[msg("Overflow")]
    Overflow,
    #[msg("Bribe too low")]
    BribeTooLow,
    #[msg("Wrong gate, the guard refuses your bribe")]
    WrongGate,
    #[msg("Already crossed the border")]
    AlreadyCrossed,
    #[msg("You already have a visa")]
    AlreadyHasVisa,
}
