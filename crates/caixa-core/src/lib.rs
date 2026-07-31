//! Caixa shared Solana substrate for ZeroClaw `wasm32-wasip2` tool plugins.
//!
//! Pure core is host-testable with `cargo test` (no wasm toolchain, no network).
//! WASM transport (`waki`) is compiled only for `target_family = "wasm"`.

pub mod base58;
pub mod base64;
pub mod encode;
pub mod memo;
pub mod output;
pub mod pay;
pub mod pubkey;
pub mod quote;
pub mod rpc;
pub mod shortvec;
pub mod spl;
pub mod tx;

pub use encode::Writer;
pub use memo::{build_invoice_memo, memo_contains_invoice};
pub use output::{shape_output, MAX_OUTPUT_CHARS};
pub use pay::{build_solana_pay_url, phantom_browse_https, solana_pay_qr_https, PayRequest};
pub use pubkey::{
    associated_token_program, get_associated_token_address, memo_program, system_program,
    token_program, usdc_mint_mainnet, Pubkey, SYSTEM_PROGRAM_ID,
};
pub use quote::{format_usdc, quote_brl_to_usdc, usdc_to_base_units, QuoteInput, QuoteResult};
pub use rpc::{
    HttpGet, MockHttpGet, MockTransport, RpcClient, RpcError, RpcTransport, SignatureInfo,
    TxMetaBrief,
};
pub use spl::{
    advance_nonce_instruction, build_spl_transfer_plan, SplTransferPlan, SplTransferRequest,
};
pub use tx::{build_legacy_unsigned_tx, AccountMeta, Instruction, TxBuildInput, TxBuildOutput};

#[cfg(target_family = "wasm")]
pub use rpc::{WakiHttpGet, WakiTransport};
