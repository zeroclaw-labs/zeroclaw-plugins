//! Pure logic for `nonce-vault-init`.
//!
//! A durable nonce account is the "waiting room" every Aval transaction sits
//! in while a human decides. This tool builds the one-time setup transaction
//! that creates it. Two properties matter:
//!
//! - **No second keypair.** The account address is derived with
//!   `createAccountWithSeed` from the human authority itself, so the only
//!   signer that ever exists is the human wallet. The agent cannot know a
//!   secret because there is no secret to know.
//! - **This is the only Aval transaction that uses a recent blockhash** (the
//!   nonce cannot anchor its own creation), so the summary tells the human to
//!   sign it promptly. Everything after this lives on durable time.

use std::collections::HashMap;

use crate::core::amount::{format_amount, LAMPORTS_PER_SOL_DECIMALS};
use crate::core::codec::b64_encode;
use crate::core::instruction::{create_account_with_seed, initialize_nonce_account};
use crate::core::message::{compile_message, serialize_unsigned_transaction};
use crate::core::nonce::{parse_nonce_account, NONCE_ACCOUNT_SIZE};
use crate::core::pubkey::{create_with_seed, system_program, Pubkey};
use crate::core::rpc::{HttpPost, Rpc};

pub const DEFAULT_SEED: &str = "aval-0";

// deny_unknown_fields closes the argument surface: a prompt-injected model
// cannot smuggle override flags this plugin never defined. Host-contract
// assumption: the host injects only `__config`; a new injected key must be
// added here explicitly (wit/v0 is unfrozen, so this is a pinned assumption).
#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct InitArgs {
    /// The human wallet that will own and sign for the nonce account.
    pub authority: String,
    /// Optional seed label; distinct seeds yield distinct nonce accounts,
    /// letting one authority run several approval lanes in parallel.
    #[serde(default)]
    pub seed: Option<String>,
    #[serde(rename = "__config", default)]
    pub config: HashMap<String, String>,
}

#[derive(Debug)]
pub struct InitOutcome {
    pub nonce_account: String,
    /// `None` when the account already exists and is initialized.
    pub transaction_base64: Option<String>,
    pub summary: String,
}

pub fn build_init<H: HttpPost>(http: &H, args: &InitArgs) -> Result<InitOutcome, String> {
    let rpc_url = args
        .config
        .get("rpc_url")
        .cloned()
        .ok_or("no rpc_url configured; set it in this plugin's config section")?;
    let rpc = Rpc::new(http, &rpc_url);

    let authority = Pubkey::from_base58(args.authority.trim())
        .map_err(|e| format!("authority rejected: {e}"))?;
    let seed = args
        .seed
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SEED);
    if !seed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("seed may only contain letters, digits, '-' and '_'".into());
    }

    let nonce_account = create_with_seed(&authority, seed, &system_program())?;

    // Idempotence: if the vault already exists, report it instead of building
    // a transaction that would fail on-chain.
    if let Some(existing) = rpc.get_account(&nonce_account)? {
        return match parse_nonce_account(&existing.data) {
            Ok(state) if state.authority == authority => Ok(InitOutcome {
                nonce_account: nonce_account.to_base58(),
                transaction_base64: None,
                summary: format!(
                    "Nonce vault {} already exists for authority {} (seed {seed:?}). \
                     Nothing to sign — durable_tx_build can use it now.",
                    nonce_account.short(),
                    authority.short()
                ),
            }),
            Ok(_) => Err(format!(
                "account {} exists but its nonce authority is not {}",
                nonce_account.to_base58(),
                authority.short()
            )),
            Err(e) => Err(format!(
                "account {} exists but is not a usable nonce account: {e}",
                nonce_account.to_base58()
            )),
        };
    }

    let rent = rpc.get_minimum_balance_for_rent_exemption(NONCE_ACCOUNT_SIZE)?;
    let blockhash = rpc.get_latest_blockhash()?;

    let instructions = vec![
        create_account_with_seed(
            &authority,
            &nonce_account,
            seed,
            rent,
            NONCE_ACCOUNT_SIZE,
            &system_program(),
        ),
        initialize_nonce_account(&nonce_account, &authority),
    ];
    let message = compile_message(&authority, &instructions, &blockhash);
    let tx = serialize_unsigned_transaction(&message);

    Ok(InitOutcome {
        nonce_account: nonce_account.to_base58(),
        transaction_base64: Some(b64_encode(&tx)),
        summary: format!(
            "Setup transaction built: creates durable nonce vault {} for authority {} \
             (seed {seed:?}, rent {} SOL, reclaimable by the authority). Sign promptly — \
             this setup step is the only Aval transaction that expires; every payment \
             built afterwards is durable.",
            nonce_account.short(),
            authority.short(),
            format_amount(rent, LAMPORTS_PER_SOL_DECIMALS)
        ),
    })
}

pub fn parameters_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "authority": {
                "type": "string",
                "description": "Base58 wallet address that will own the nonce account and sign every payment."
            },
            "seed": {
                "type": "string",
                "description": "Optional label (letters, digits, '-', '_') so one wallet can run several vaults. Default \"aval-0\"."
            }
        },
        "required": ["authority"]
    })
}
