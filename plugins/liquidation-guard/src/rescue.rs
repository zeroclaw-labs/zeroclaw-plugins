//! Pure klend/farms instruction encoder for the unsigned repay/deposit
//! rescue transactions, plus fixed-offset reserve-account extraction.
//!
//! No I/O: the only inputs are already-fetched reserve account bytes
//! (base64) and a caller-supplied blockhash string. Custody story
//! (safety invariant 3, amended per the v11-deposit-encoder ruling):
//! encoders exist for exactly the five instructions the field-observed
//! mainnet repay/deposit flows use (`refresh_reserve`,
//! `refresh_obligation`, `repay_obligation_liquidity_v2`,
//! `deposit_reserve_liquidity_and_obligation_collateral_v2`, plus the
//! opt-in `AdvanceNonceAccount`/compute-budget ixs) — funds can only move
//! FROM the user's wallet INTO the user's own position. Withdraw, borrow,
//! and liquidate remain structurally impossible: no encoder for them exists
//! anywhere in this module. That is grep-verifiable against this crate alone —
//! the README's safety invariant 3 lists the four instruction names and the
//! grep to run. They are deliberately NOT spelled out here: writing the check
//! into the code under test would put the very strings it searches for into
//! `src/`, and the grep would then match this comment and pass trivially.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------
// Program ids.
// ---------------------------------------------------------------------

/// Kamino Lend (klend) program.
const KLEND_PROGRAM_ID: &str = "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD";
/// Kamino farms program (obligation farm accounting for reward-bearing
/// reserves).
const FARMS_PROGRAM_ID: &str = "FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr";
/// SPL associated-token-account program; derives `user_source_liquidity`.
const ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// Sysvar instructions account (klend reads it for CPI-guard checks).
const SYSVAR_INSTRUCTIONS_ID: &str = "Sysvar1nstructions1111111111111111111111111";
/// All-zero pubkey: the Kamino "unset" sentinel for optional oracle/farm
/// account fields.
const ZERO_PUBKEY: &str = "11111111111111111111111111111111";
/// Native Solana compute-budget program: `SetComputeUnitLimit` (tag `2`)
/// and `SetComputeUnitPrice` (tag `3`), no accounts on either.
const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
/// Native Solana system program: owns every durable-nonce account and
/// implements `AdvanceNonceAccount` (tag `4u32` LE, no args). Same all-zero
/// pubkey as [`ZERO_PUBKEY`], spelled out separately here since the two
/// constants mean different things (klend's "unset" sentinel vs. an actual
/// program id used in an instruction).
const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
/// `RecentBlockhashes` sysvar: read (not written) by `AdvanceNonceAccount`.
const SYSVAR_RECENT_BLOCKHASHES_ID: &str = "SysvarRecentB1ockHashes11111111111111111111";
/// `AdvanceNonceAccount` instruction tag (system program instruction index
/// 4), `u32` LE, no args.
const ADVANCE_NONCE_ACCOUNT_TAG: u32 = 4;
/// Classic SPL Token program. `build_deposit_tx`'s
/// `collateral_token_program` account: Kamino's internal cToken
/// (collateral) mint is always managed via the classic SPL Token program
/// (only the underlying liquidity mint can be Token-2022) — a documented
/// single-sample assumption — see the README's Future work section.
const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// Compute-unit ceiling for the priority-fee `SetComputeUnitLimit`
/// instruction. `pub(crate)` so `report::render_rescue` can name the same
/// number it built into the tx.
///
/// This ceiling MUST cover the largest obligation this encoder can build
/// for, not just the golden fixture, because setting it *lowers* the budget:
/// with no `SetComputeUnitLimit` the runtime grants
/// `min(instruction_count * 200_000, 1_400_000)`, so the fee-off 8-instruction
/// build already gets 1,400,000 CU. A ceiling pinned to the 6-reserve fixture
/// (261,070 consumed -> the old 400,000) meant that *opting into* a priority
/// fee could push a many-reserve rescue over the limit and fail it with
/// `ExceededMaxComputeUnits` — while the same rescue succeeded with the fee
/// off. Exactly backwards for a knob whose whole purpose is landing during
/// congestion.
///
/// Derivation from both goldens' `meta` (`repay_tx.json` = 261,070 over 6
/// reserves; `deposit_tx.json`'s terminal instruction is the more expensive
/// of the two at ~90k including the farms CPI):
///   per reserve  ~23k (`refresh_reserve`) + ~14k (its slot in
///                `refresh_obligation`)  = ~37k
///   terminal     ~90k (deposit; repay is ~41k)
///   worst case   13 reserves (klend's 8 deposits + 5 borrows):
///                13 * 37k + 90k = 571k, * 1.5 margin = 857k
/// Rounded to 900_000 — above the worst case, still well under the 1,400,000
/// runtime maximum, and still a real reduction (the prioritization fee is
/// charged on the requested limit, so it stays far below asking for the max).
pub(crate) const RESCUE_CU_LIMIT: u32 = 900_000;

// ---------------------------------------------------------------------
// Anchor discriminators: instructions are `sha256("global:<snake_name>")
// [..8]`, account types are `sha256("account:<TypeName>")[..8]`.
// Recomputed in `tests/rescue_golden.rs::discriminator_derivation`.
// ---------------------------------------------------------------------

/// `sha256("global:refresh_reserve")[..8]` = `02da8aeb4fc91966`.
const DISC_REFRESH_RESERVE: [u8; 8] = [0x02, 0xda, 0x8a, 0xeb, 0x4f, 0xc9, 0x19, 0x66];
/// `sha256("global:refresh_obligation")[..8]` = `218493e497c04859`.
const DISC_REFRESH_OBLIGATION: [u8; 8] = [0x21, 0x84, 0x93, 0xe4, 0x97, 0xc0, 0x48, 0x59];
/// `sha256("global:repay_obligation_liquidity_v2")[..8]` = `74aed54cb435d290`.
const DISC_REPAY_OBLIGATION_LIQUIDITY_V2: [u8; 8] =
    [0x74, 0xae, 0xd5, 0x4c, 0xb4, 0x35, 0xd2, 0x90];
/// `sha256("global:deposit_reserve_liquidity_and_obligation_collateral_v2")
/// [..8]` = `d8e0bf1bcc9766af`.
const DISC_DEPOSIT_RESERVE_LIQUIDITY_AND_OBLIGATION_COLLATERAL_V2: [u8; 8] =
    [0xd8, 0xe0, 0xbf, 0x1b, 0xcc, 0x97, 0x66, 0xaf];
/// `sha256("account:Reserve")[..8]` = `2bf2ccca1af73b7f` — validates the
/// reserve account blob before trusting any fixed-offset field below.
const DISC_ACCOUNT_RESERVE: [u8; 8] = [0x2b, 0xf2, 0xcc, 0xca, 0x1a, 0xf7, 0x3b, 0x7f];

// ---------------------------------------------------------------------
// Reserve account layout (klend-interface `state/reserve.rs`, repr(C)+Pod,
// size-asserted 8616 bytes past the 8-byte account discriminator = 8624
// bytes total). Offsets validated live against every demo reserve and,
// for `mint_decimals`, across all 58 market reserves.
// ---------------------------------------------------------------------

const RESERVE_ACCOUNT_LEN: usize = 8624;

const OFF_LENDING_MARKET: usize = 24 + 8;
/// Collateral-side farm (distinct from [`OFF_FARM_DEBT`]) — used by
/// `deposit_reserve_liquidity_and_obligation_collateral_v2`'s
/// `obligation_farm_user_state`/`reserve_farm_state` accounts. Empirically
/// confirmed: `lending_market` (32B @ 32) is immediately followed by
/// `farm_collateral` (32B @ 64) then `farm_debt` (32B @ 96) — see the job
/// report's account-mapping table.
const OFF_FARM_COLLATERAL: usize = 56 + 8;
const OFF_FARM_DEBT: usize = 88 + 8;
const OFF_LIQUIDITY_MINT: usize = 120 + 8;
const OFF_SUPPLY_VAULT: usize = 152 + 8;
const OFF_MINT_DECIMALS: usize = 264 + 8;
const OFF_TOKEN_PROGRAM: usize = 400 + 8;
/// `ReserveCollateral.mint_pubkey` — located empirically
/// by searching a captured reserve's raw bytes for the known
/// `reserve_coll_mint` PDA value; cross-checked against that PDA the same
/// way [`OFF_SUPPLY_VAULT`] is cross-checked against `reserve_liq_supply`.
const OFF_COLLATERAL_MINT: usize = 2552 + 8;
/// `ReserveCollateral.supply_vault` — same empirical/cross-check method as
/// [`OFF_COLLATERAL_MINT`].
const OFF_COLLATERAL_SUPPLY: usize = 2592 + 8;
const OFF_SCOPE_PRICE_FEED: usize = 5104 + 8;
const OFF_SWITCHBOARD_PRICE: usize = 5152 + 8;
const OFF_SWITCHBOARD_TWAP: usize = 5184 + 8;
const OFF_PYTH_PRICE: usize = 5216 + 8;

// ---------------------------------------------------------------------
// Public types (frozen interface contract).
// ---------------------------------------------------------------------

/// One reserve's accounts, extracted at fixed offsets from its raw account
/// bytes. See [`extract_reserve_accounts`].
#[derive(Debug, Clone)]
pub struct ReserveAccounts {
    pub reserve: String,
    pub lending_market: String,
    pub pyth: Option<String>,
    pub switchboard: Option<String>,
    pub switchboard_twap: Option<String>,
    pub scope_prices: Option<String>,
    pub farm_debt: Option<String>,
    /// Collateral-side farm — `None` when this reserve isn't farm-enabled
    /// on the collateral side. Distinct from `farm_debt` (debt-side).
    pub farm_collateral: Option<String>,
    pub liquidity_mint: String,
    pub supply_vault: String,
    pub token_program: String,
    pub mint_decimals: u8,
    /// `ReserveCollateral.mint_pubkey` (the reserve's internal cToken
    /// mint) — only read by [`build_deposit_tx`].
    pub collateral_mint: String,
    /// `ReserveCollateral.supply_vault` (the reserve's own collateral
    /// vault — `reserve_destination_deposit_collateral`) — only read by
    /// [`build_deposit_tx`].
    pub collateral_supply: String,
}

/// The result of [`build_repay_tx`] or [`build_deposit_tx`]: an unsigned
/// legacy transaction plus the amount it moves. `repay_ui` is the frozen
/// field name from the original repay-only interface (reused verbatim per
/// the v11-deposit-encoder interface contract); [`build_deposit_tx`]
/// populates it with the deposit ui amount.
#[derive(Debug, Clone)]
pub struct RescuePlan {
    pub tx_base64: String,
    pub amount_native: u64,
    pub repay_ui: f64,
}

/// Everything needed to advance a durable nonce and stamp its stored value
/// into the built transaction's message. Built by `guard::run_rescue` from
/// a fail-closed read + parse of the configured `nonce_account` — see
/// [`parse_nonce_account`].
#[derive(Debug, Clone)]
pub struct NonceInfo {
    /// The durable-nonce account itself (writable in the advance ix).
    pub account: String,
    /// The nonce's authority — must equal the tx fee payer (`owner`) or the
    /// built tx would be unusable; enforced by `parse_nonce_account`.
    pub authority: String,
    /// The nonce value currently stored on-chain, base58 — becomes the
    /// message's blockhash field instead of a fetched recent blockhash.
    pub stored_value: String,
}

/// Optional per-tx knobs for [`build_repay_tx`]. `Default` leaves every
/// knob off, so a caller that never opts in gets byte-identical output to
/// pre-v1.1.
#[derive(Debug, Clone, Default)]
pub struct TxOptions {
    /// `Some(microlamports_per_cu)` prepends `SetComputeUnitLimit(
    /// RESCUE_CU_LIMIT)` + `SetComputeUnitPrice(fee)` ahead of the repay
    /// instructions. `None` (the default): no compute-budget instructions.
    pub priority_fee_microlamports: Option<u64>,
    /// `Some(info)` prepends an `AdvanceNonceAccount` instruction as
    /// instruction index 0 (ahead of any compute-budget instructions) and
    /// stamps `info.stored_value` into the message's blockhash field
    /// instead of the `blockhash_base58` argument. `None` (the default):
    /// no nonce instruction, `blockhash_base58` used as-is.
    pub nonce: Option<NonceInfo>,
}

// ---------------------------------------------------------------------
// Reserve-account extraction.
// ---------------------------------------------------------------------

/// Extracts oracle/farm/token-program/mint accounts from a reserve's raw
/// account bytes (base64, as served by
/// `/kamino-market/reserves/account-data`). Fail-closed: validates length,
/// the account discriminator, and that the embedded `lending_market`
/// matches `expected_market` before trusting any offset — an
/// unresolvable or mismatched account is always a typed `Err`, never a
/// guess.
pub fn extract_reserve_accounts(
    reserve_pubkey: &str,
    base64_data: &str,
    expected_market: &str,
) -> Result<ReserveAccounts, String> {
    let raw = base64_decode(base64_data)?;
    if raw.len() != RESERVE_ACCOUNT_LEN {
        return Err(format!(
            "reserve {reserve_pubkey}: expected {RESERVE_ACCOUNT_LEN} account bytes, got {}",
            raw.len()
        ));
    }
    if raw[0..8] != DISC_ACCOUNT_RESERVE {
        return Err(format!(
            "reserve {reserve_pubkey}: unexpected account discriminator {:02x?}, expected {:02x?}",
            &raw[0..8],
            DISC_ACCOUNT_RESERVE
        ));
    }

    let lending_market = pubkey_at(&raw, OFF_LENDING_MARKET)?;
    if lending_market != expected_market {
        return Err(format!(
            "reserve {reserve_pubkey}: lending_market {lending_market} != expected market {expected_market}"
        ));
    }

    Ok(ReserveAccounts {
        reserve: reserve_pubkey.to_string(),
        lending_market,
        pyth: optional_pubkey_at(&raw, OFF_PYTH_PRICE)?,
        switchboard: optional_pubkey_at(&raw, OFF_SWITCHBOARD_PRICE)?,
        switchboard_twap: optional_pubkey_at(&raw, OFF_SWITCHBOARD_TWAP)?,
        scope_prices: optional_pubkey_at(&raw, OFF_SCOPE_PRICE_FEED)?,
        farm_debt: optional_pubkey_at(&raw, OFF_FARM_DEBT)?,
        farm_collateral: optional_pubkey_at(&raw, OFF_FARM_COLLATERAL)?,
        liquidity_mint: pubkey_at(&raw, OFF_LIQUIDITY_MINT)?,
        supply_vault: pubkey_at(&raw, OFF_SUPPLY_VAULT)?,
        token_program: pubkey_at(&raw, OFF_TOKEN_PROGRAM)?,
        mint_decimals: mint_decimals_at(&raw, OFF_MINT_DECIMALS)?,
        collateral_mint: pubkey_at(&raw, OFF_COLLATERAL_MINT)?,
        collateral_supply: pubkey_at(&raw, OFF_COLLATERAL_SUPPLY)?,
    })
}

fn pubkey_at(raw: &[u8], offset: usize) -> Result<String, String> {
    let slice = raw
        .get(offset..offset + 32)
        .ok_or_else(|| format!("account blob too short for pubkey at offset {offset}"))?;
    let bytes: [u8; 32] = slice.try_into().expect("slice length checked above");
    Ok(bs58::encode(bytes).into_string())
}

fn optional_pubkey_at(raw: &[u8], offset: usize) -> Result<Option<String>, String> {
    let pk = pubkey_at(raw, offset)?;
    Ok(if pk == ZERO_PUBKEY { None } else { Some(pk) })
}

fn mint_decimals_at(raw: &[u8], offset: usize) -> Result<u8, String> {
    let slice = raw
        .get(offset..offset + 8)
        .ok_or_else(|| format!("account blob too short for mint_decimals at offset {offset}"))?;
    let bytes: [u8; 8] = slice.try_into().expect("slice length checked above");
    let v = u64::from_le_bytes(bytes);
    u8::try_from(v).map_err(|_| format!("mint_decimals out of u8 range: {v}"))
}

// ---------------------------------------------------------------------
// v1 limitation: referrer obligations need `referrer_token_state`
// remaining accounts on `refresh_obligation`, which this encoder does not
// implement. Call before `build_repay_tx` and refuse the rescue rather
// than guess at the extra accounts.
// ---------------------------------------------------------------------

/// Refuses a rescue when the obligation has a referrer (v1 limitation —
/// `referrer_token_state` remaining accounts on `refresh_obligation` are
/// not implemented).
pub fn refuse_referrer_obligation(referrer: Option<&str>) -> Result<(), String> {
    match referrer {
        Some(r) => Err(format!(
            "rescue v1 does not support obligations with a referrer ({r}): \
             refresh_obligation referrer_token_state remaining accounts are not implemented"
        )),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------
// Durable nonce (v1.1): fail-closed parse of a system-program nonce
// account's raw bytes, plus the `AdvanceNonceAccount` instruction builder.
// Layout (80 bytes, matches solana-sdk's `nonce::state::Versions` wrapping
// `nonce::state::Data`, `repr(C)`+bincode, all fields little-endian):
//   [0..4)   u32 version, must be 1
//   [4..8)   u32 state,   must be 1 (initialized)
//   [8..40)  32-byte authority pubkey
//   [40..72) 32-byte durable nonce value (a blockhash)
//   [72..80) u64 lamports-per-signature (fee-calculator remnant, unused here)
// ---------------------------------------------------------------------

/// Parses a durable-nonce account's owner + raw bytes into its stored
/// nonce value (base58), fail-closed: any mismatch against the expected
/// system-program owner, exact 80-byte length, version, initialized state,
/// or authority is a typed `Err` naming the specific failure — never a
/// guess, never a silent fallback. `expected_authority` is the tx fee payer
/// (`owner` in [`build_repay_tx`]): an unauthorized nonce would build a tx
/// nobody can advance, so it's refused here instead.
pub fn parse_nonce_account(
    owner: &str,
    data: &[u8],
    expected_authority: &str,
) -> Result<String, String> {
    if owner != SYSTEM_PROGRAM_ID {
        return Err(format!(
            "nonce account owner {owner} != system program {SYSTEM_PROGRAM_ID}"
        ));
    }
    if data.len() != 80 {
        return Err(format!("nonce account data length {} != 80", data.len()));
    }
    let version = u32::from_le_bytes(data[0..4].try_into().expect("length checked above"));
    if version != 1 {
        return Err(format!("nonce account version {version} != 1"));
    }
    let state = u32::from_le_bytes(data[4..8].try_into().expect("length checked above"));
    if state != 1 {
        return Err(format!("nonce account state {state} != 1 (initialized)"));
    }
    let authority_bytes: [u8; 32] = data[8..40].try_into().expect("length checked above");
    let authority = bs58::encode(authority_bytes).into_string();
    if authority != expected_authority {
        return Err(format!(
            "nonce authority {authority} != expected {expected_authority}"
        ));
    }
    let stored_value_bytes: [u8; 32] = data[40..72].try_into().expect("length checked above");
    Ok(bs58::encode(stored_value_bytes).into_string())
}

/// Builds the `AdvanceNonceAccount` instruction: system program, accounts
/// `[nonce account (writable), RecentBlockhashes sysvar (readonly),
/// authority (readonly signer)]`, data = `u32` LE `4`.
fn advance_nonce_account_ix(nonce_account: &str, authority: &str) -> Ix {
    Ix {
        program_id: SYSTEM_PROGRAM_ID.to_string(),
        accounts: vec![
            AccountRef {
                pubkey: nonce_account.to_string(),
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                pubkey: SYSVAR_RECENT_BLOCKHASHES_ID.to_string(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: authority.to_string(),
                is_signer: true,
                is_writable: false,
            },
        ],
        data: ADVANCE_NONCE_ACCOUNT_TAG.to_le_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------
// PDA / ATA derivation (RULING 1): sha2 + curve25519-dalek off-curve
// check, no solana-sdk.
// ---------------------------------------------------------------------

fn is_on_curve(bytes: &[u8; 32]) -> bool {
    curve25519_dalek::edwards::CompressedEdwardsY(*bytes)
        .decompress()
        .is_some()
}

/// `find_program_address`: for bump 255..=0, hash
/// `seeds ‖ [bump] ‖ program_id ‖ "ProgramDerivedAddress"`; the first
/// candidate not on the ed25519 curve wins.
fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> Result<[u8; 32], String> {
    for bump in (0u8..=255).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program_id);
        hasher.update(b"ProgramDerivedAddress");
        let hash: [u8; 32] = hasher.finalize().into();
        if !is_on_curve(&hash) {
            return Ok(hash);
        }
    }
    Err("no off-curve PDA found in bump range 0..=255".to_string())
}

fn derive_pda(seeds: &[&[u8]], program_id: &str) -> Result<String, String> {
    let pid = pubkey_bytes(program_id)?;
    let addr = find_program_address(seeds, &pid)?;
    Ok(bs58::encode(addr).into_string())
}

/// Derives an associated-token-account address for `(owner, mint,
/// token_program)` — the single home for ATA derivation in this crate (F8).
/// `guard::run_rescue` calls this for the optional wallet-balance repay
/// cap; [`build_repay_tx`] derives the same address internally for
/// `user_source_liquidity`.
pub(crate) fn derive_ata(owner: &str, mint: &str, token_program: &str) -> Result<String, String> {
    derive_pda(
        &[
            &pubkey_bytes(owner)?,
            &pubkey_bytes(token_program)?,
            &pubkey_bytes(mint)?,
        ],
        ATA_PROGRAM_ID,
    )
}

/// Derives the klend lending-market-authority PDA (seeds `["lma", market]`)
/// — shared by [`build_repay_tx`] and [`build_deposit_tx`], both of which
/// name this account as their last non-farms account.
fn lending_market_authority(market: &str) -> Result<String, String> {
    derive_pda(&[b"lma", &pubkey_bytes(market)?], KLEND_PROGRAM_ID)
}

fn pubkey_bytes(s: &str) -> Result<[u8; 32], String> {
    let v = bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("bad base58 value {s:?}: {e}"))?;
    v.try_into()
        .map_err(|v: Vec<u8>| format!("value {s:?} decodes to {} bytes, expected 32", v.len()))
}

// ---------------------------------------------------------------------
// Instruction / transaction assembly.
// ---------------------------------------------------------------------

struct AccountRef {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

struct Ix {
    program_id: String,
    accounts: Vec<AccountRef>,
    data: Vec<u8>,
}

fn optional_account(opt: &Option<String>) -> AccountRef {
    match opt {
        Some(pk) => AccountRef {
            pubkey: pk.clone(),
            is_signer: false,
            is_writable: false,
        },
        None => AccountRef {
            pubkey: KLEND_PROGRAM_ID.to_string(),
            is_signer: false,
            is_writable: false,
        },
    }
}

/// `ComputeBudget111...` `SetComputeUnitLimit`: tag `2u8` ++ `u32` LE
/// compute-unit ceiling, no accounts.
fn compute_unit_limit_ix(limit: u32) -> Ix {
    let mut data = vec![2u8];
    data.extend_from_slice(&limit.to_le_bytes());
    Ix {
        program_id: COMPUTE_BUDGET_PROGRAM_ID.to_string(),
        accounts: Vec::new(),
        data,
    }
}

/// `ComputeBudget111...` `SetComputeUnitPrice`: tag `3u8` ++ `u64` LE
/// microlamports-per-CU price, no accounts.
fn compute_unit_price_ix(price: u64) -> Ix {
    let mut data = vec![3u8];
    data.extend_from_slice(&price.to_le_bytes());
    Ix {
        program_id: COMPUTE_BUDGET_PROGRAM_ID.to_string(),
        accounts: Vec::new(),
        data,
    }
}

/// Builds the unsigned base64 repay transaction: `refresh_reserve` per
/// obligation reserve (repay reserve last), `refresh_obligation`, then
/// `repay_obligation_liquidity_v2` — exactly the field-observed mainnet
/// instruction sequence. `obligation_reserves` carries every deposit and
/// borrow reserve of the obligation, deposits then borrows (the same
/// order `refresh_obligation`'s remaining accounts use); this function
/// reorders that same set internally to put the repay reserve last for
/// `refresh_reserve`. Any unresolvable account or failed cross-check is a
/// typed `Err` — this encoder never guesses. `options` is opt-in: with
/// `TxOptions::default()` (no priority fee, no nonce), the built bytes are
/// byte-identical to a pre-v1.1 build. `options.nonce` (when set) always
/// wins instruction slot 0 over `options.priority_fee_microlamports`'s
/// compute-budget ixs, and its stored value replaces `blockhash_base58` in
/// the message.
#[allow(clippy::too_many_arguments)]
pub fn build_repay_tx(
    owner: &str,
    obligation: &str,
    market: &str,
    obligation_reserves: &[ReserveAccounts],
    repay_reserve: &str,
    amount_native: u64,
    blockhash_base58: &str,
    options: &TxOptions,
) -> Result<RescuePlan, String> {
    if obligation_reserves.is_empty() {
        return Err("obligation_reserves is empty".to_string());
    }
    let repay = obligation_reserves
        .iter()
        .find(|r| r.reserve == repay_reserve)
        .ok_or_else(|| format!("repay_reserve {repay_reserve} not found in obligation_reserves"))?;

    // Cross-check both the offset table and the PDA derivation at once:
    // the extracted supply_vault must equal the derived
    // reserve_liq_supply PDA. Deviation from the issue's stated seeds
    // (`["reserve_liq_supply", reserve]`, which also matches klend's
    // current open-source `handler_init_reserve.rs`): live-verified
    // against all 6 reserves in `tests/fixtures/reserve_accounts.json`,
    // the on-chain vault is actually seeded by `["reserve_liq_supply",
    // lending_market, liquidity_mint]` (each match confirmed by full
    // 32-byte hash equality across the whole 0..=255 bump range, so this
    // isn't a canonical-bump artifact) — evidently this market's vaults
    // predate a later per-reserve migration, or share a vault per
    // (market, mint). The golden test is the source of truth here, not
    // the current mainline source.
    let derived_supply_vault = derive_pda(
        &[
            b"reserve_liq_supply",
            &pubkey_bytes(market)?,
            &pubkey_bytes(&repay.liquidity_mint)?,
        ],
        KLEND_PROGRAM_ID,
    )?;
    if derived_supply_vault != repay.supply_vault {
        return Err(format!(
            "repay reserve {repay_reserve}: derived reserve_liq_supply PDA {derived_supply_vault} \
             != extracted supply_vault {}",
            repay.supply_vault
        ));
    }

    let lma = lending_market_authority(market)?;
    let user_source_liquidity = derive_ata(owner, &repay.liquidity_mint, &repay.token_program)?;

    let mut ixs = Vec::new();

    // 1. refresh_reserve — one per obligation reserve, repay reserve LAST.
    let mut refresh_order: Vec<&ReserveAccounts> = obligation_reserves
        .iter()
        .filter(|r| r.reserve != repay_reserve)
        .collect();
    refresh_order.push(repay);
    for r in refresh_order {
        ixs.push(Ix {
            program_id: KLEND_PROGRAM_ID.to_string(),
            accounts: vec![
                AccountRef {
                    pubkey: r.reserve.clone(),
                    is_signer: false,
                    is_writable: true,
                },
                AccountRef {
                    pubkey: market.to_string(),
                    is_signer: false,
                    is_writable: false,
                },
                optional_account(&r.pyth),
                optional_account(&r.switchboard),
                optional_account(&r.switchboard_twap),
                optional_account(&r.scope_prices),
            ],
            data: DISC_REFRESH_RESERVE.to_vec(),
        });
    }

    // 2. refresh_obligation — market r, obligation W, remaining = ALL
    //    obligation reserves writable, in the caller's given order
    //    (deposits then borrows).
    let mut refresh_obligation_accounts = vec![
        AccountRef {
            pubkey: market.to_string(),
            is_signer: false,
            is_writable: false,
        },
        AccountRef {
            pubkey: obligation.to_string(),
            is_signer: false,
            is_writable: true,
        },
    ];
    for r in obligation_reserves {
        refresh_obligation_accounts.push(AccountRef {
            pubkey: r.reserve.clone(),
            is_signer: false,
            is_writable: true,
        });
    }
    ixs.push(Ix {
        program_id: KLEND_PROGRAM_ID.to_string(),
        accounts: refresh_obligation_accounts,
        data: DISC_REFRESH_OBLIGATION.to_vec(),
    });

    // 3. repay_obligation_liquidity_v2 — exactly 13 accounts, no
    //    remaining accounts.
    let (farm_user_state, farm_state) = match &repay.farm_debt {
        Some(fd) => (
            derive_pda(
                &[b"user", &pubkey_bytes(fd)?, &pubkey_bytes(obligation)?],
                FARMS_PROGRAM_ID,
            )?,
            fd.clone(),
        ),
        None => (KLEND_PROGRAM_ID.to_string(), KLEND_PROGRAM_ID.to_string()),
    };
    let farm_accounts_writable = repay.farm_debt.is_some();

    let mut repay_data = DISC_REPAY_OBLIGATION_LIQUIDITY_V2.to_vec();
    repay_data.extend_from_slice(&amount_native.to_le_bytes());

    ixs.push(Ix {
        program_id: KLEND_PROGRAM_ID.to_string(),
        accounts: vec![
            AccountRef {
                pubkey: owner.to_string(),
                is_signer: true,
                is_writable: true,
            },
            AccountRef {
                pubkey: obligation.to_string(),
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                pubkey: market.to_string(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: repay.reserve.clone(),
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                pubkey: repay.liquidity_mint.clone(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: repay.supply_vault.clone(),
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                pubkey: user_source_liquidity,
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                pubkey: repay.token_program.clone(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: SYSVAR_INSTRUCTIONS_ID.to_string(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: farm_user_state,
                is_signer: false,
                is_writable: farm_accounts_writable,
            },
            AccountRef {
                pubkey: farm_state,
                is_signer: false,
                is_writable: farm_accounts_writable,
            },
            AccountRef {
                pubkey: lma,
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: FARMS_PROGRAM_ID.to_string(),
                is_signer: false,
                is_writable: false,
            },
        ],
        data: repay_data,
    });

    // Opt-in priority fee: prepend exactly two compute-budget ixs ahead of
    // everything else. `None` (the default) leaves `ixs` — and therefore
    // the serialized bytes — identical to the pre-v1.1 build.
    if let Some(fee) = options.priority_fee_microlamports {
        let mut prefixed = Vec::with_capacity(ixs.len() + 2);
        prefixed.push(compute_unit_limit_ix(RESCUE_CU_LIMIT));
        prefixed.push(compute_unit_price_ix(fee));
        prefixed.extend(ixs);
        ixs = prefixed;
    }

    // Opt-in durable nonce: `AdvanceNonceAccount` MUST be instruction index
    // 0 (Solana requires the nonce advance first in the tx), so this
    // prepend runs last — after the priority-fee prepend above — putting
    // any compute-budget ixs right after it. The message blockhash field
    // carries the stored nonce value instead of `blockhash_base58`. `None`
    // (the default) leaves both `ixs` and the blockhash field untouched.
    let effective_blockhash = match &options.nonce {
        Some(nonce) => {
            let mut prefixed = Vec::with_capacity(ixs.len() + 1);
            prefixed.push(advance_nonce_account_ix(&nonce.account, &nonce.authority));
            prefixed.extend(ixs);
            ixs = prefixed;
            nonce.stored_value.as_str()
        }
        None => blockhash_base58,
    };

    let tx_base64 = serialize_legacy_tx(&ixs, owner, effective_blockhash)?;
    let repay_ui = amount_native as f64 / 10f64.powi(repay.mint_decimals as i32);

    Ok(RescuePlan {
        tx_base64,
        amount_native,
        repay_ui,
    })
}

/// Builds the unsigned base64 deposit transaction: `refresh_reserve` per
/// obligation reserve (deposit reserve last, deduped when the deposit
/// reserve is already one of the obligation's own reserves),
/// `refresh_obligation` (remaining accounts = `obligation_reserves` exactly
/// as given — never including a deposit reserve that isn't already part of
/// the obligation), then
/// `deposit_reserve_liquidity_and_obligation_collateral_v2` — the
/// field-observed mainnet deposit instruction sequence (captured tx
/// signature
/// `5wcNDh7HcUVEipGHk2xnzMigX1LwkPBPvsMJPvukUU3mxGkFTe1WYY3PMdHnufwCHkeDnUa1gECsYccEDuUDF7np`).
/// `deposit_reserve` is given directly rather than looked up inside
/// `obligation_reserves` (unlike `build_repay_tx`'s `repay_reserve: &str`
/// lookup, which errors when absent): the captured ground-truth tx deposits
/// into a reserve that was not yet one of the obligation's reserves, so a
/// lookup-and-error-if-absent contract would wrongly reject a legitimate
/// deposit-into-new-reserve shape. Every derivable account is PDA
/// cross-checked against its extracted counterpart, fail-closed on
/// mismatch, same style as `build_repay_tx`'s supply-vault check. `options`
/// composes exactly as in `build_repay_tx`.
#[allow(clippy::too_many_arguments)]
pub fn build_deposit_tx(
    owner: &str,
    obligation: &str,
    market: &str,
    obligation_reserves: &[ReserveAccounts],
    deposit_reserve: &ReserveAccounts,
    amount_native: u64,
    blockhash_base58: &str,
    options: &TxOptions,
) -> Result<RescuePlan, String> {
    let market_bytes = pubkey_bytes(market)?;
    let mint_bytes = pubkey_bytes(&deposit_reserve.liquidity_mint)?;

    let derived_liq_supply = derive_pda(
        &[b"reserve_liq_supply", &market_bytes, &mint_bytes],
        KLEND_PROGRAM_ID,
    )?;
    if derived_liq_supply != deposit_reserve.supply_vault {
        return Err(format!(
            "deposit reserve {}: derived reserve_liq_supply PDA {derived_liq_supply} \
             != extracted supply_vault {}",
            deposit_reserve.reserve, deposit_reserve.supply_vault
        ));
    }

    let derived_coll_mint = derive_pda(
        &[b"reserve_coll_mint", &market_bytes, &mint_bytes],
        KLEND_PROGRAM_ID,
    )?;
    if derived_coll_mint != deposit_reserve.collateral_mint {
        return Err(format!(
            "deposit reserve {}: derived reserve_coll_mint PDA {derived_coll_mint} \
             != extracted collateral_mint {}",
            deposit_reserve.reserve, deposit_reserve.collateral_mint
        ));
    }

    let derived_coll_supply = derive_pda(
        &[b"reserve_coll_supply", &market_bytes, &mint_bytes],
        KLEND_PROGRAM_ID,
    )?;
    if derived_coll_supply != deposit_reserve.collateral_supply {
        return Err(format!(
            "deposit reserve {}: derived reserve_coll_supply PDA {derived_coll_supply} \
             != extracted collateral_supply {}",
            deposit_reserve.reserve, deposit_reserve.collateral_supply
        ));
    }

    let lma = lending_market_authority(market)?;
    let user_source_liquidity = derive_ata(
        owner,
        &deposit_reserve.liquidity_mint,
        &deposit_reserve.token_program,
    )?;

    let mut ixs = Vec::new();

    // 1. refresh_reserve — one per obligation reserve, deposit reserve
    //    LAST, deduped when it's already one of the obligation's reserves.
    let mut refresh_order: Vec<&ReserveAccounts> = obligation_reserves
        .iter()
        .filter(|r| r.reserve != deposit_reserve.reserve)
        .collect();
    refresh_order.push(deposit_reserve);
    for r in refresh_order {
        ixs.push(Ix {
            program_id: KLEND_PROGRAM_ID.to_string(),
            accounts: vec![
                AccountRef {
                    pubkey: r.reserve.clone(),
                    is_signer: false,
                    is_writable: true,
                },
                AccountRef {
                    pubkey: market.to_string(),
                    is_signer: false,
                    is_writable: false,
                },
                optional_account(&r.pyth),
                optional_account(&r.switchboard),
                optional_account(&r.switchboard_twap),
                optional_account(&r.scope_prices),
            ],
            data: DISC_REFRESH_RESERVE.to_vec(),
        });
    }

    // 2. refresh_obligation — remaining accounts = obligation_reserves
    //    exactly as given, never appending the deposit reserve (job
    //    report: a brand-new deposit reserve is not yet part of the
    //    obligation's own reserve set).
    let mut refresh_obligation_accounts = vec![
        AccountRef {
            pubkey: market.to_string(),
            is_signer: false,
            is_writable: false,
        },
        AccountRef {
            pubkey: obligation.to_string(),
            is_signer: false,
            is_writable: true,
        },
    ];
    for r in obligation_reserves {
        refresh_obligation_accounts.push(AccountRef {
            pubkey: r.reserve.clone(),
            is_signer: false,
            is_writable: true,
        });
    }
    ixs.push(Ix {
        program_id: KLEND_PROGRAM_ID.to_string(),
        accounts: refresh_obligation_accounts,
        data: DISC_REFRESH_OBLIGATION.to_vec(),
    });

    // 3. deposit_reserve_liquidity_and_obligation_collateral_v2 — exactly
    //    17 accounts, matching the captured mainnet tx, no remaining
    //    accounts.
    let (farm_user_state, farm_state) = match &deposit_reserve.farm_collateral {
        Some(fc) => (
            derive_pda(
                &[b"user", &pubkey_bytes(fc)?, &pubkey_bytes(obligation)?],
                FARMS_PROGRAM_ID,
            )?,
            fc.clone(),
        ),
        None => (KLEND_PROGRAM_ID.to_string(), KLEND_PROGRAM_ID.to_string()),
    };
    let farm_accounts_writable = deposit_reserve.farm_collateral.is_some();

    let mut deposit_data = DISC_DEPOSIT_RESERVE_LIQUIDITY_AND_OBLIGATION_COLLATERAL_V2.to_vec();
    deposit_data.extend_from_slice(&amount_native.to_le_bytes());

    ixs.push(Ix {
        program_id: KLEND_PROGRAM_ID.to_string(),
        accounts: vec![
            AccountRef {
                pubkey: owner.to_string(),
                is_signer: true,
                is_writable: true,
            },
            AccountRef {
                pubkey: obligation.to_string(),
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                pubkey: market.to_string(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: lma,
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: deposit_reserve.reserve.clone(),
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                pubkey: deposit_reserve.liquidity_mint.clone(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: deposit_reserve.supply_vault.clone(),
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                pubkey: deposit_reserve.collateral_mint.clone(),
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                pubkey: deposit_reserve.collateral_supply.clone(),
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                pubkey: user_source_liquidity,
                is_signer: false,
                is_writable: true,
            },
            AccountRef {
                // placeholder_user_destination_collateral: always unset —
                // v1 never mints a separate destination-collateral account
                // to the user (Kamino tracks collateral internally).
                pubkey: KLEND_PROGRAM_ID.to_string(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: TOKEN_PROGRAM_ID.to_string(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: deposit_reserve.token_program.clone(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: SYSVAR_INSTRUCTIONS_ID.to_string(),
                is_signer: false,
                is_writable: false,
            },
            AccountRef {
                pubkey: farm_user_state,
                is_signer: false,
                is_writable: farm_accounts_writable,
            },
            AccountRef {
                pubkey: farm_state,
                is_signer: false,
                is_writable: farm_accounts_writable,
            },
            AccountRef {
                pubkey: FARMS_PROGRAM_ID.to_string(),
                is_signer: false,
                is_writable: false,
            },
        ],
        data: deposit_data,
    });

    if let Some(fee) = options.priority_fee_microlamports {
        let mut prefixed = Vec::with_capacity(ixs.len() + 2);
        prefixed.push(compute_unit_limit_ix(RESCUE_CU_LIMIT));
        prefixed.push(compute_unit_price_ix(fee));
        prefixed.extend(ixs);
        ixs = prefixed;
    }

    let effective_blockhash = match &options.nonce {
        Some(nonce) => {
            let mut prefixed = Vec::with_capacity(ixs.len() + 1);
            prefixed.push(advance_nonce_account_ix(&nonce.account, &nonce.authority));
            prefixed.extend(ixs);
            ixs = prefixed;
            nonce.stored_value.as_str()
        }
        None => blockhash_base58,
    };

    let tx_base64 = serialize_legacy_tx(&ixs, owner, effective_blockhash)?;
    let deposit_ui = amount_native as f64 / 10f64.powi(deposit_reserve.mint_decimals as i32);

    Ok(RescuePlan {
        tx_base64,
        amount_native,
        repay_ui: deposit_ui,
    })
}

/// Merges an account's signer/writable requirement into `meta`, tracking
/// first-occurrence order in `order`. A key seen again with a stronger
/// requirement (writable, or signer) upgrades its recorded privilege —
/// the same key can only carry one privilege level for the whole
/// transaction.
fn touch(
    order: &mut Vec<String>,
    meta: &mut HashMap<String, (bool, bool)>,
    pubkey: &str,
    is_signer: bool,
    is_writable: bool,
) {
    match meta.get_mut(pubkey) {
        Some(entry) => {
            entry.0 |= is_signer;
            entry.1 |= is_writable;
        }
        None => {
            meta.insert(pubkey.to_string(), (is_signer, is_writable));
            order.push(pubkey.to_string());
        }
    }
}

/// Serializes a legacy (non-versioned) unsigned transaction:
/// `[compact-u16 sig count = 1][64 zero bytes][message]` where message =
/// header + compact-u16 key count + keys (writable signers, readonly
/// signers, writable non-signers, readonly non-signers) + blockhash +
/// compact-u16 ix count + per-instruction
/// `(program_id index, compact-u16 account count, account indexes,
/// compact-u16 data len, data)`. Output is base64 of the whole thing.
fn serialize_legacy_tx(ixs: &[Ix], owner: &str, blockhash_base58: &str) -> Result<String, String> {
    let mut order: Vec<String> = Vec::new();
    let mut meta: HashMap<String, (bool, bool)> = HashMap::new();

    // Fee payer is always present and always the strongest privilege
    // (writable signer), touched first so it lands at index 0.
    touch(&mut order, &mut meta, owner, true, true);
    for ix in ixs {
        for a in &ix.accounts {
            touch(&mut order, &mut meta, &a.pubkey, a.is_signer, a.is_writable);
        }
        touch(&mut order, &mut meta, &ix.program_id, false, false);
    }

    let mut writable_signers = Vec::new();
    let mut readonly_signers = Vec::new();
    let mut writable_nonsigners = Vec::new();
    let mut readonly_nonsigners = Vec::new();
    for pk in &order {
        let (is_signer, is_writable) = meta[pk];
        match (is_signer, is_writable) {
            (true, true) => writable_signers.push(pk.clone()),
            (true, false) => readonly_signers.push(pk.clone()),
            (false, true) => writable_nonsigners.push(pk.clone()),
            (false, false) => readonly_nonsigners.push(pk.clone()),
        }
    }

    let num_required_signatures = (writable_signers.len() + readonly_signers.len()) as u8;
    let num_readonly_signed_accounts = readonly_signers.len() as u8;
    let num_readonly_unsigned_accounts = readonly_nonsigners.len() as u8;

    let mut all_keys = Vec::new();
    all_keys.extend(writable_signers);
    all_keys.extend(readonly_signers);
    all_keys.extend(writable_nonsigners);
    all_keys.extend(readonly_nonsigners);

    if all_keys.len() > 255 {
        return Err(format!(
            "too many accounts for u8 indexing: {}",
            all_keys.len()
        ));
    }

    // Exactly one 64-byte signature slot is written below, and
    // `Transaction::sanitize` requires
    // `signatures.len() >= header.num_required_signatures`. The fee payer is
    // the only intended signer. A second one can only appear if a caller
    // hands in a `NonceInfo` whose `authority` is not the fee payer — the
    // gate for that lives in `parse_nonce_account`, a different function,
    // and this encoder is `pub`. Refuse rather than emit a transaction whose
    // header promises more signatures than the wire carries.
    if num_required_signatures != 1 {
        return Err(format!(
            "expected exactly one required signature (the fee payer), computed \
             {num_required_signatures}: every signer other than the fee payer must be \
             removed before serialization"
        ));
    }

    let mut index_of: HashMap<&str, u8> = HashMap::new();
    for (i, pk) in all_keys.iter().enumerate() {
        index_of.insert(pk.as_str(), i as u8);
    }

    let mut message = Vec::new();
    message.push(num_required_signatures);
    message.push(num_readonly_signed_accounts);
    message.push(num_readonly_unsigned_accounts);
    write_compact_u16(&mut message, all_keys.len() as u16);
    for pk in &all_keys {
        message.extend_from_slice(&pubkey_bytes(pk)?);
    }
    message.extend_from_slice(&pubkey_bytes(blockhash_base58)?);

    write_compact_u16(&mut message, ixs.len() as u16);
    for ix in ixs {
        let program_idx = *index_of
            .get(ix.program_id.as_str())
            .ok_or_else(|| format!("program id {} missing from key list", ix.program_id))?;
        message.push(program_idx);
        write_compact_u16(&mut message, ix.accounts.len() as u16);
        for a in &ix.accounts {
            let idx = *index_of
                .get(a.pubkey.as_str())
                .ok_or_else(|| format!("account {} missing from key list", a.pubkey))?;
            message.push(idx);
        }
        write_compact_u16(&mut message, ix.data.len() as u16);
        message.extend_from_slice(&ix.data);
    }

    let mut wire = Vec::new();
    write_compact_u16(&mut wire, 1); // exactly one signature slot
    wire.extend_from_slice(&[0u8; 64]); // unsigned: zeroed
    wire.extend_from_slice(&message);

    Ok(base64_encode(&wire))
}

/// Solana's compact-u16 ("shortvec") encoding: 7 payload bits per byte,
/// MSB continuation bit.
fn write_compact_u16(out: &mut Vec<u8>, mut n: u16) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            break;
        }
    }
}

// ---------------------------------------------------------------------
// Base64 (hand-rolled: no base64 crate in the pinned dependency set).
// Exposed so `tests/rescue_golden.rs` can decode this module's own
// output to verify the zeroed-signature-slot invariant.
// ---------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(format!("invalid base64 byte: {c}")),
        } as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}
