use anchor_lang::prelude::*;

declare_id!("AgntPass1111111111111111111111111111111111111");

/// Maximum length of a passport ID (e.g., "ap_a622a643aa71")
const MAX_PASSPORT_ID_LEN: usize = 32;
/// Maximum length of a credential type string
const MAX_CREDENTIAL_TYPE_LEN: usize = 64;

#[program]
pub mod agentpass_anchor {
    use super::*;

    /// Register a Solana wallet as the authority for an AgentPass passport.
    /// One wallet can control one passport; one passport can have one on-chain binding.
    pub fn register_passport(
        ctx: Context<RegisterPassport>,
        passport_id: String,
    ) -> Result<()> {
        require!(
            passport_id.len() <= MAX_PASSPORT_ID_LEN && !passport_id.is_empty(),
            AgentPassError::InvalidPassportId
        );

        let passport = &mut ctx.accounts.passport_account;
        passport.passport_id = passport_id;
        passport.authority = ctx.accounts.authority.key();
        passport.credential_count = 0;
        passport.created_at = Clock::get()?.unix_timestamp;
        passport.bump = ctx.bumps.passport_account;

        emit!(PassportRegistered {
            passport_id: passport.passport_id.clone(),
            authority: passport.authority,
        });

        Ok(())
    }

    /// Anchor a credential hash on-chain. Only the passport authority can anchor.
    pub fn anchor_credential(
        ctx: Context<AnchorCredential>,
        credential_hash: [u8; 32],
        issuer: String,
        subject: String,
        credential_type: String,
    ) -> Result<()> {
        require!(
            issuer.len() <= MAX_PASSPORT_ID_LEN && !issuer.is_empty(),
            AgentPassError::InvalidPassportId
        );
        require!(
            subject.len() <= MAX_PASSPORT_ID_LEN && !subject.is_empty(),
            AgentPassError::InvalidPassportId
        );
        require!(
            credential_type.len() <= MAX_CREDENTIAL_TYPE_LEN && !credential_type.is_empty(),
            AgentPassError::InvalidCredentialType
        );

        let anchor = &mut ctx.accounts.credential_anchor;
        anchor.passport = ctx.accounts.passport_account.key();
        anchor.credential_hash = credential_hash;
        anchor.issuer = issuer;
        anchor.subject = subject;
        anchor.credential_type = credential_type;
        anchor.anchored_at = Clock::get()?.unix_timestamp;
        anchor.revoked = false;
        anchor.bump = ctx.bumps.credential_anchor;

        let passport = &mut ctx.accounts.passport_account;
        passport.credential_count = passport.credential_count.checked_add(1)
            .ok_or(AgentPassError::Overflow)?;

        emit!(CredentialAnchored {
            passport_id: passport.passport_id.clone(),
            credential_hash,
            issuer: anchor.issuer.clone(),
            subject: anchor.subject.clone(),
            credential_type: anchor.credential_type.clone(),
        });

        Ok(())
    }

    /// Revoke a previously anchored credential. Only the passport authority can revoke.
    pub fn revoke_credential(ctx: Context<RevokeCredential>) -> Result<()> {
        require!(
            !ctx.accounts.credential_anchor.revoked,
            AgentPassError::AlreadyRevoked
        );

        ctx.accounts.credential_anchor.revoked = true;

        emit!(CredentialRevoked {
            credential_hash: ctx.accounts.credential_anchor.credential_hash,
        });

        Ok(())
    }
}

// === Accounts ===

#[account]
#[derive(InitSpace)]
pub struct PassportAccount {
    #[max_len(32)]
    pub passport_id: String,
    pub authority: Pubkey,
    pub credential_count: u64,
    pub created_at: i64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct CredentialAnchor {
    pub passport: Pubkey,
    pub credential_hash: [u8; 32],
    #[max_len(32)]
    pub issuer: String,
    #[max_len(32)]
    pub subject: String,
    #[max_len(64)]
    pub credential_type: String,
    pub anchored_at: i64,
    pub revoked: bool,
    pub bump: u8,
}

// === Contexts ===

#[derive(Accounts)]
#[instruction(passport_id: String)]
pub struct RegisterPassport<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + PassportAccount::INIT_SPACE,
        seeds = [b"passport", passport_id.as_bytes()],
        bump,
    )]
    pub passport_account: Account<'info, PassportAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(credential_hash: [u8; 32])]
pub struct AnchorCredential<'info> {
    #[account(
        mut,
        has_one = authority,
        seeds = [b"passport", passport_account.passport_id.as_bytes()],
        bump = passport_account.bump,
    )]
    pub passport_account: Account<'info, PassportAccount>,
    #[account(
        init,
        payer = authority,
        space = 8 + CredentialAnchor::INIT_SPACE,
        seeds = [b"credential", passport_account.key().as_ref(), &credential_hash],
        bump,
    )]
    pub credential_anchor: Account<'info, CredentialAnchor>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokeCredential<'info> {
    #[account(
        has_one = authority,
        seeds = [b"passport", passport_account.passport_id.as_bytes()],
        bump = passport_account.bump,
    )]
    pub passport_account: Account<'info, PassportAccount>,
    #[account(
        mut,
        constraint = credential_anchor.passport == passport_account.key(),
    )]
    pub credential_anchor: Account<'info, CredentialAnchor>,
    pub authority: Signer<'info>,
}

// === Events ===

#[event]
pub struct PassportRegistered {
    pub passport_id: String,
    pub authority: Pubkey,
}

#[event]
pub struct CredentialAnchored {
    pub passport_id: String,
    pub credential_hash: [u8; 32],
    pub issuer: String,
    pub subject: String,
    pub credential_type: String,
}

#[event]
pub struct CredentialRevoked {
    pub credential_hash: [u8; 32],
}

// === Errors ===

#[error_code]
pub enum AgentPassError {
    #[msg("Invalid passport ID")]
    InvalidPassportId,
    #[msg("Invalid credential type")]
    InvalidCredentialType,
    #[msg("Credential already revoked")]
    AlreadyRevoked,
    #[msg("Arithmetic overflow")]
    Overflow,
}
