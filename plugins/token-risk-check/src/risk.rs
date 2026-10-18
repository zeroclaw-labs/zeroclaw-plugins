use crate::extensions::{MintExtensions, TransferFeeConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct RiskAssessment {
    pub risk: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConcentrationSignal {
    NotChecked,
    ZeroSupply,
    Calculated(u32),
}

pub fn top_holder_concentration_bps(
    top_holders: &[(String, u128)],
    total_supply: u128,
) -> ConcentrationSignal {
    if total_supply == 0 {
        return ConcentrationSignal::ZeroSupply;
    }

    let mut sum: u128 = 0;
    for (_, amount) in top_holders {
        sum = sum.saturating_add(*amount);
    }

    let bps = (sum.saturating_mul(10_000)) / total_supply;
    // Cap at 10000 just in case
    ConcentrationSignal::Calculated(std::cmp::min(bps as u32, 10_000))
}

pub fn score(
    ext: &MintExtensions,
    known_hooks: &[String],
    concentration: ConcentrationSignal,
    hook_program_info: Option<&crate::program::HookProgramInfo>,
    slot_consistency: Option<&crate::rpc::SlotConsistency>,
) -> RiskAssessment {
    let mut reasons = Vec::new();
    let mut is_red = false;
    let mut is_amber = false;

    match concentration {
        ConcentrationSignal::NotChecked => {
            // Do nothing
        }
        ConcentrationSignal::ZeroSupply => {
            // Zero supply treated as red because we cannot assess distribution, not because zero supply is itself malicious.
            is_red = true;
            reasons.push("Mint supply is zero or unreadable — cannot assess distribution.".to_string());
        }
        ConcentrationSignal::Calculated(bps) => {
            // > 80% (8000 bps): High risk of immediate rug pull/price manipulation since a small group controls supply
            if bps > 8000 {
                is_red = true;
                reasons.push(format!("Top holders control >80% of supply ({} bps). Extreme concentration risk.", bps));
            } 
            // > 50% (5000 bps): Significant concentration, susceptible to large price swings if whales sell
            else if bps > 5000 {
                is_amber = true;
                reasons.push(format!("Top holders control >50% of supply ({} bps). High concentration risk.", bps));
            }
            // > 30% (3000 bps): Notable concentration, worth flagging but standard for early projects
            else if bps > 3000 {
                reasons.push(format!("Top holders control >30% of supply ({} bps). Notable concentration.", bps));
            }
        }
    }

    if ext.permanent_delegate.is_some() {
        is_red = true;
        reasons.push("Permanent delegate is enabled; tokens can be burned or transferred by the delegate at any time.".to_string());
    }

    if let Some(state) = ext.default_account_state {
        match state {
            2 => {
                is_red = true;
                reasons.push("Default account state is Frozen; all new accounts are frozen by default.".to_string());
            }
            0 | 1 => {
                // 0 = Uninitialized, 1 = Initialized (unfrozen). These are standard/safe states.
            }
            _ => {
                is_amber = true;
                reasons.push(format!("Unknown default account state: {}", state));
            }
        }
    }

    if let Some(TransferFeeConfig { transfer_fee_basis_points, withdraw_withheld_authority: _ }) = ext.transfer_fee_config {
        // 1000 bps = 10%. We flag >10% as unusually high (amber) because legitimate protocols 
        // typically charge 0.1% to 1%, whereas honeypots/scam tokens often charge extreme fees (e.g., 99%).
        // 5000 bps = 50%. This is an extreme fee and acts as a soft honeypot, so we flag it as red.
        if transfer_fee_basis_points > 5000 {
            is_red = true;
            reasons.push(format!("Transfer fee is exceptionally high ({} bps) - possible honeypot.", transfer_fee_basis_points));
        } else if transfer_fee_basis_points > 1000 {
            is_amber = true;
            reasons.push(format!("Transfer fee is unusually high ({} bps).", transfer_fee_basis_points));
        } else if transfer_fee_basis_points > 0 {
            reasons.push(format!("Transfer fee of {} bps is enabled.", transfer_fee_basis_points));
        }
    }

    if let Some(hook) = ext.transfer_hook_program_id {
        let hook_str = bs58::encode(hook).into_string();
        if known_hooks.contains(&hook_str) {
            if let Some(info) = hook_program_info {
                if !info.is_upgradeable || info.upgrade_authority.is_none() {
                    reasons.push(format!("Transfer hook program is a known compliance hook ({}) and is immutable.", hook_str));
                } else {
                    is_amber = true;
                    reasons.push(format!("Recognized hook program ({}) can still be silently replaced (upgrade authority active).", hook_str));
                }
            } else {
                is_amber = true;
                reasons.push(format!("Transfer hook program ({}) is on the known-hooks allowlist, but its upgrade authority could not be verified.", hook_str));
            }
        } else {
            is_amber = true;
            reasons.push(format!("Unknown transfer hook program ({}) can arbitrarily block or revert transfers.", hook_str));
        }
    }

    if ext.mint_authority.is_some() {
        is_amber = true;
        reasons.push("Mint authority is active; supply can be inflated.".to_string());
    }

    if ext.freeze_authority.is_some() {
        is_amber = true;
        reasons.push("Freeze authority is active; individual accounts can be frozen.".to_string());
    }

    if !ext.unknown_extensions.is_empty() {
        is_amber = true;
        reasons.push(format!("Mint has {} extension type(s) not recognized by this scanner — cannot verify safety.", ext.unknown_extensions.len()));
    }

    if let Some(crate::rpc::SlotConsistency::BoundedForward(skew)) = slot_consistency {
        reasons.push(format!("Informational: Token distribution fetched {} slots after mint data. Data is slightly skewed but within acceptable bounds.", skew));
    }

    let risk = if is_red {
        "red"
    } else if is_amber {
        "amber"
    } else {
        "green"
    };

    if risk == "green" && reasons.is_empty() {
        reasons.push("No high-risk extensions found. Standard mint authorities are disabled or non-malicious.".to_string());
    }

    RiskAssessment {
        risk: risk.to_string(),
        reasons,
    }
}
