//! Pure Rust Solana/PIX helpers for ZeroClaw plugins.
//!
//! No wit-bindgen, no WASM runtime deps — safe for host unit tests and
//! thin plugin shims.

pub mod amount;
pub mod dashboard;
pub mod invoice;
pub mod pix;
pub mod reference;
pub mod rpc;
pub mod shape;
pub mod solana_pay;
pub mod status;

pub use amount::{
    compare_amount, format_brl, format_usdc, parse_decimal, AmountError, ParsedAmount,
};
pub use invoice::{
    build_invoice, resolve_mint_alias, InvoiceConfig, InvoiceRequest, InvoiceResult,
};
pub use pix::{build_pix_payload, sanitize_txid, PixParams};
pub use reference::derive_reference;
pub use rpc::{HttpTransport, ReceivedAmount, RpcClient, RpcError, SignatureInfo};
pub use shape::{sanitize_pix_key, strip_accents};
pub use solana_pay::{build_solana_pay_url, is_valid_base58_pubkey, SolanaPayParams, USDC_MINT};
pub use dashboard::{default_usdc_mint, format_dashboard, DashboardSnapshot};
pub use status::{status_from_signatures, status_from_signatures_verified, UsdcReceipt};
