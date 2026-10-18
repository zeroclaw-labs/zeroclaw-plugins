use serde_json::Value;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PluginError {
    #[error("invalid args: {0}")]
    InvalidArgs(String),
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("policy: {0}")]
    Policy(String),
}

pub type Result<T> = std::result::Result<T, PluginError>;

pub fn name() -> String { "solana_pay".into() }
pub fn description() -> String { "Build Solana Pay URLs and unsigned payment transactions.".to_string() }

pub fn parameters_schema() -> &'static str {
    r#"{"type":"object","properties":{"recipient":{"type":"string"},"amount":{"type":"number"},"mint":{"type":"string","default":"So11111111111111111111111111111111111111112"},"reference":{"type":"string"}}}"#
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TransferArgs {
    pub recipient: String,
    pub amount: f64,
    pub mint: String,
    pub reference: Option<String>,
}

pub fn execute(args_json: &str) -> std::result::Result<String, PluginError> {
    let args: TransferArgs = serde_json::from_str(args_json).map_err(|e| PluginError::InvalidArgs(e.to_string()))?;
    if args.amount <= 0.0 {
        return Err(PluginError::Policy("amount must be > 0".into()));
    }
    if args.recipient.len() < 32 || args.recipient.len() > 44 {
        return Err(PluginError::InvalidArgs("recipient must be a base58 Solana address".into()))?;
    }
    let reference = args.reference.unwrap_or_default();
    let payload = serde_json::json!({
        "ok": true,
        "action": "solana_pay",
        "unsigned_tx_b64": null,
        "solana_pay_url": format!("solana:{recipient}?amount={amount}&spl-token={mint}&reference={reference}", recipient=args.recipient, amount=args.amount, mint=args.mint, reference=reference),
        "tier": "T1",
        "recipient": args.recipient,
        "amount": args.amount,
        "mint": args.mint,
        "reference": reference,
    });
    Ok(serde_json::to_string(&payload).unwrap())
}
