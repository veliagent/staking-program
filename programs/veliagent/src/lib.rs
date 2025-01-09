use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Mint};
use anchor_lang::solana_program::system_instruction;
use solana_program::instruction::Instruction;
use solana_program::sysvar::instructions::{ID as IX_ID, load_instruction_at_checked};
pub mod utils;
pub use utils::secp256k1::*;
use solana_program::keccak;

declare_id!("FBqd9AH9gRjRFLP7ghMBXC747WxzKrbrF6qBq6qm4Muq");
#[program]
pub mod veliagent {
    pub const TOKEN_MINT: &str = "726TmaSjnFth6fEtdwfszrUDuZ8Rc2JRALRFFYhZKcL7";
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        pool.admin = ctx.accounts.owner.key();
        pool.vault_token_account = ctx.accounts.token_vault.key();
        pool.vault_sol = ctx.accounts.sol_vault.key();
        pool.enable_stake = false;

        Ok(())
    }

    pub fn set_enable_stake(
        ctx: Context<UpdateParameters>,
        enable_stake: bool,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        if pool.admin != ctx.accounts.admin.key() {
            return Err(ErrorCode::UnauthorizedAccess.into());
        }

        pool.enable_stake = enable_stake;

        Ok(())
    }

    pub fn stake(ctx: Context<Stake>, token_amount: u64, request_id: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user_stake = &mut ctx.accounts.user_stake;

        if !pool.enable_stake {
            return Err(ErrorCode::StakeNotEnabled.into());
        }

        if token_amount <= 0 {
            return Err(ErrorCode::InvalidTokenAmount.into());
        }

        if pool.vault_token_account != ctx.accounts.token_vault.key() {
            return Err(ErrorCode::InvalidTokenVault.into());
        }

        if user_stake.is_staked {
            return Err(ErrorCode::AlreadyStaked.into());
        }

        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.user_token_account.to_account_info(),
                to: ctx.accounts.token_vault.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, token_amount)?;

        user_stake.token_amount = token_amount;
        user_stake.request_id = request_id;
        user_stake.is_staked = true;

        Ok(())
    }

    pub fn claim(ctx: Context<Claim>, request_id: u64, amount_token: u64, amount_sol: u64, eth_address: [u8; 20], sig: [u8; 64], recovery_id: u8) -> Result<()> {
        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&ctx.accounts.user.key().as_ref());
        encoded.extend_from_slice(&request_id.to_be_bytes());
        encoded.extend_from_slice(&amount_token.to_be_bytes());
        encoded.extend_from_slice(&amount_sol.to_be_bytes());

        // Compute Keccak256 hash
        let msg_digest = keccak::hash(&encoded).0;

        // Prepend with Ethereum signed message prefix
        let eth_signed_message_prefix = b"\x19Ethereum Signed Message:\n32";
        let mut actual_message = Vec::new();
        actual_message.extend_from_slice(eth_signed_message_prefix);
        actual_message.extend_from_slice(&msg_digest);

        utils::verify_secp256k1_ix(&ix, &eth_address, &actual_message, &sig, recovery_id)?;

        let user_claim = &mut ctx.accounts.user_claim;
        let user_stake = &mut ctx.accounts.user_stake;

        if !user_stake.is_staked {
            return Err(ErrorCode::NotStaked.into());
        }
        if user_claim.is_success {
            return Err(ErrorCode::IdClaimed.into());
        }

        if amount_token > 0 {
            let token_vault = &ctx.accounts.token_vault;
            let token_mint_address = ctx.accounts.token_mint.key();

            let (pda, bump) = Pubkey::find_program_address(
                &[token_mint_address.as_ref()],
                ctx.program_id
            );

            let seeds = &[token_mint_address.as_ref(), &[bump]];
            let signer = &[&seeds[..]];

            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.token_vault.to_account_info(),
                    authority: ctx.accounts.token_vault.to_account_info(),
                    to: ctx.accounts.user_token_account.to_account_info(),
                },
                signer,
            );
            token::transfer(cpi_ctx, amount_token)?;
        }

        if amount_sol > 0 {
            **ctx.accounts.sol_vault.try_borrow_mut_lamports()? = ctx.accounts.sol_vault.lamports().checked_sub(amount_sol).ok_or(ErrorCode::InsufficientFunds)?;
            **ctx.accounts.user.try_borrow_mut_lamports()? = ctx.accounts.user.lamports().checked_add(amount_sol).ok_or(ErrorCode::Overflow)?;
        }

        user_claim.sol_amount = amount_sol;
        user_claim.token_amount = amount_token;
        user_claim.request_id = request_id;
        user_claim.is_success = true;

        Ok(())
    }

    pub fn withdraw_sol(ctx: Context<WithdrawSol>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        if pool.admin != ctx.accounts.admin.key() {
            return Err(ErrorCode::UnauthorizedAccess.into());
        }

        // Transfer SOL from PDA to recipient
        **ctx.accounts.sol_vault.try_borrow_mut_lamports()? = ctx.accounts.sol_vault.lamports()
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;

        **ctx.accounts.admin.try_borrow_mut_lamports()? = ctx.accounts.admin.lamports()
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;

        Ok(())
    }
}

#[account]
pub struct POOL {
    pub admin: Pubkey,
    pub vault_token_account: Pubkey,
    pub vault_sol: Pubkey,
    pub enable_stake: bool,
}

#[account]
pub struct UserStake {
    pub token_amount: u64,
    pub request_id: u64,
    pub is_staked: bool
}

#[account]
pub struct UserClaim {
    pub sol_amount: u64,
    pub token_amount: u64,
    pub request_id: u64,
    pub is_success: bool
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + 32 + 32 + 1,
        seeds = [b"pool", owner.key().as_ref()],
        bump
    )]
    pub pool: Account<'info, POOL>,

    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        init,
        payer = owner,
        seeds = [ TOKEN_MINT.parse::< Pubkey > ().unwrap().as_ref() ],
        bump,
        token::mint = token_mint,
        token::authority = token_vault,
    )]
    pub token_vault: Account<'info, TokenAccount>,

    /// CHECK: Sol vault PDA
    #[account(
        init,
        payer = owner,
        space = 0,
        seeds = [b"sol_vault"],
        bump
    )]
    pub sol_vault: UncheckedAccount<'info>,

    #[account(
        address = TOKEN_MINT.parse::< Pubkey > ().unwrap(),
    )]
    pub token_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateParameters<'info> {
    #[account(mut)]
    pub pool: Account<'info, POOL>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct Stake<'info> {
    #[account(mut)]
    pub pool: Account<'info, POOL>,

    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        constraint = token_vault.mint == token_mint.key()
    )]
    pub token_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = user_token_account.mint == token_mint.key(),
        constraint = user_token_account.owner == user.key()
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(
        address = TOKEN_MINT.parse::< Pubkey > ().unwrap(),
    )]
    pub token_mint: Account<'info, Mint>,

    #[account(
        init,
        payer = user,
        space = 8 + 8 + 8 + 1,
        seeds = [b"user_stake", pool.key().as_ref(), user.key().as_ref()],
        bump
    )]
    pub user_stake: Account<'info, UserStake>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(request_id: u64)]
pub struct Claim<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        constraint = token_vault.mint == token_mint.key()
    )]
    pub token_vault: Account<'info, TokenAccount>,
    /// CHECK: This is the native SOL vault, we only transfer from it
    #[account(mut)]
    pub sol_vault: UncheckedAccount<'info>,

    #[account(
        mut,
        constraint = user_token_account.mint == token_mint.key(),
        constraint = user_token_account.owner == user.key()
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(
        address = TOKEN_MINT.parse::< Pubkey > ().unwrap(),
    )]
    pub token_mint: Account<'info, Mint>,

    #[account(mut)]
    pub user_stake: Account<'info, UserStake>,

    #[account(
        init,
        payer = user,
        space = 8 + 8 + 8 + 8 + 1,
        seeds = [b"user_claim", user.key().as_ref(), request_id.to_le_bytes().as_ref()],
        bump
    )]
    pub user_claim: Account<'info, UserClaim>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,

    /// CHECK: ix_sysvar
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct WithdrawSol<'info> {
    pub admin: Signer<'info>,

    #[account(mut)]
    pub pool: Account<'info, POOL>,

    /// CHECK: This is the native SOL vault, we only transfer from it
    #[account(mut)]
    pub sol_vault: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized access!")]
    UnauthorizedAccess,
    #[msg("Invalid Token amount!")]
    InvalidTokenAmount,
    #[msg("TokenVault is invalid!")]
    InvalidTokenVault,
    #[msg("User staked!")]
    AlreadyStaked,
    #[msg("Stake is not enable!")]
    StakeNotEnabled,
    #[msg("Insufficient claim!")]
    InsufficientFunds,
    #[msg("It is over flow!")]
    Overflow,
    #[msg("User is not staked!")]
    NotStaked,
    #[msg("Id has been claimed by the user!")]
    IdClaimed
}