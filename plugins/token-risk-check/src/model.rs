use serde::{Deserialize, Serialize};

pub const MAX_REASONS: usize = 12;
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Red,
    Amber,
    Green,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Reason {
    pub code: &'static str,
    pub severity: Verdict,
    pub message: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorityEvidence {
    pub status: &'static str,
    pub address: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConcentrationEvidence {
    pub status: &'static str,
    pub top_owner_bps: Option<u16>,
    pub observed_owner_count: usize,
    pub observed_account_count: usize,
    pub observed_amount: String,
    pub top_n_lower_bound: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LiquidityEvidence {
    pub status: &'static str,
    pub indexed_pair_count: usize,
    pub positive_pair_count: usize,
    pub total_liquidity_usd_micros: Option<String>,
    pub lp_control_status: &'static str,
}

impl LiquidityEvidence {
    pub fn unknown() -> Self {
        Self {
            status: "unknown",
            indexed_pair_count: 0,
            positive_pair_count: 0,
            total_liquidity_usd_micros: None,
            lp_control_status: "unknown_not_inferred_from_indexed_pairs",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransferFeeEvidence {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdraw_withheld_authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withheld_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_schedule: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_basis_points: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_maximum_fee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newer_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newer_basis_points: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newer_maximum_fee: Option<String>,
}

impl TransferFeeEvidence {
    fn status(status: &'static str) -> Self {
        Self {
            status,
            config_authority: None,
            withdraw_withheld_authority: None,
            withheld_amount: None,
            observed_epoch: None,
            selected_schedule: None,
            selected_basis_points: None,
            selected_maximum_fee: None,
            newer_epoch: None,
            newer_basis_points: None,
            newer_maximum_fee: None,
        }
    }

    pub fn absent() -> Self {
        Self::status("absent")
    }

    pub fn unknown() -> Self {
        Self::status("unknown")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransferHookEvidence {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermanentDelegateEvidence {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtensionEvidence {
    pub token_2022: bool,
    pub transfer_fee: TransferFeeEvidence,
    pub transfer_hook: TransferHookEvidence,
    pub permanent_delegate: PermanentDelegateEvidence,
    pub unknown_extension_types: Vec<u16>,
}

impl ExtensionEvidence {
    pub fn unknown() -> Self {
        Self {
            token_2022: false,
            transfer_fee: TransferFeeEvidence::unknown(),
            transfer_hook: TransferHookEvidence {
                status: "unknown",
                authority: None,
                program_id: None,
            },
            permanent_delegate: PermanentDelegateEvidence {
                status: "unknown",
                address: None,
            },
            unknown_extension_types: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsistencyEvidence {
    pub status: &'static str,
    pub mint_slot: Option<u64>,
    pub largest_accounts_slot: Option<u64>,
    pub owner_accounts_slot: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Assessment {
    pub version: &'static str,
    pub mint: String,
    pub verdict: Verdict,
    pub complete: bool,
    pub token_program: &'static str,
    pub supply: Option<String>,
    pub decimals: Option<u8>,
    pub mint_authority: AuthorityEvidence,
    pub freeze_authority: AuthorityEvidence,
    pub concentration: ConcentrationEvidence,
    pub liquidity: LiquidityEvidence,
    pub extensions: ExtensionEvidence,
    pub consistency: ConsistencyEvidence,
    pub reasons: Vec<Reason>,
    pub limitations: Vec<&'static str>,
}

impl Assessment {
    pub fn unknown(mint: &str, code: &'static str, message: &'static str) -> Self {
        Self {
            version: "1",
            mint: mint.to_string(),
            verdict: Verdict::Amber,
            complete: false,
            token_program: "unknown",
            supply: None,
            decimals: None,
            mint_authority: AuthorityEvidence {
                status: "unknown",
                address: None,
            },
            freeze_authority: AuthorityEvidence {
                status: "unknown",
                address: None,
            },
            concentration: ConcentrationEvidence {
                status: "unknown",
                top_owner_bps: None,
                observed_owner_count: 0,
                observed_account_count: 0,
                observed_amount: "0".to_string(),
                top_n_lower_bound: true,
            },
            liquidity: LiquidityEvidence::unknown(),
            extensions: ExtensionEvidence::unknown(),
            consistency: ConsistencyEvidence {
                status: "unknown",
                mint_slot: None,
                largest_accounts_slot: None,
                owner_accounts_slot: None,
            },
            reasons: vec![Reason {
                code,
                severity: Verdict::Amber,
                message,
            }],
            limitations: vec![
                "holder concentration is a lower bound over the RPC top-N token accounts",
                "indexed liquidity does not prove LP lock, burn, ownership, sellability, or price impact",
            ],
        }
    }

    pub fn push_reason(&mut self, reason: Reason) {
        if self.reasons.len() < MAX_REASONS && !self.reasons.iter().any(|r| r.code == reason.code) {
            self.reasons.push(reason);
        }
    }
}

pub fn serialize_bounded(assessment: &Assessment) -> String {
    let encoded = serde_json::to_string(assessment).expect("assessment is always serializable");
    if encoded.len() <= MAX_OUTPUT_BYTES {
        return encoded;
    }
    serde_json::json!({
        "version": "1",
        "mint": assessment.mint,
        "verdict": "amber",
        "complete": false,
        "reasons": [{
            "code": "OUTPUT_LIMIT",
            "severity": "amber",
            "message": "assessment exceeded the bounded output limit"
        }]
    })
    .to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelArgs {
    pub mint: String,
}
