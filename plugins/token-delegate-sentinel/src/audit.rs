use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::address::Address;
use crate::config::SentinelConfig;
use crate::rpc::{fetch_genesis_hash, fetch_mints, fetch_token_accounts, HttpTransport, RpcError};
use crate::token_account::{AccountState, MintAccount, ProgramKind, TokenAccount};

pub const MAX_OUTPUT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Amber,
    Red,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Finding {
    pub risk: Risk,
    pub token_account: Address,
    pub token_program: ProgramKind,
    pub mint: Address,
    pub delegate: Address,
    pub token_state: AccountState,
    pub balance: String,
    pub allowance: String,
    pub immediate_exposure: String,
    pub dormant_allowance: String,
    pub mint_decimals: Option<u8>,
    pub allowlisted: bool,
    pub zero_allowance: bool,
    pub wrapped_native: bool,
    pub nft_like: bool,
    #[serde(skip)]
    immediate_exposure_base_units: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RiskCounts {
    pub red: usize,
    pub amber: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SnapshotSlots {
    pub minimum: u64,
    pub maximum: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditReport {
    pub status: &'static str,
    pub owner: Address,
    pub genesis_hash: Address,
    pub snapshot_slots: SnapshotSlots,
    pub accounts_scanned: usize,
    pub delegated_accounts: usize,
    pub risk_counts: RiskCounts,
    pub authority_fingerprint: String,
    pub findings: Vec<Finding>,
    pub findings_omitted: usize,
    pub transaction_created: bool,
    pub transaction_submitted: bool,
}

impl AuditReport {
    pub fn finding_count(&self) -> usize {
        self.delegated_accounts
    }

    pub fn render(&self) -> String {
        if self.delegated_accounts == 0 {
            return format!(
                "GREEN — no token-account delegate fields found across {} SPL Token and Token-2022 account(s) (finalized slots {}–{}). Authority fingerprint: {}. No transaction was created or submitted.",
                self.accounts_scanned,
                self.snapshot_slots.minimum,
                self.snapshot_slots.maximum,
                self.authority_fingerprint
            );
        }
        let mut output = format!(
            "{} — {} token delegate finding{} (finalized slots {}–{}).\n",
            self.status.to_ascii_uppercase(),
            self.delegated_accounts,
            if self.delegated_accounts == 1 {
                ""
            } else {
                "s"
            },
            self.snapshot_slots.minimum,
            self.snapshot_slots.maximum
        );
        for finding in &self.findings {
            let risk = match finding.risk {
                Risk::Red => "RED",
                Risk::Amber => "AMBER",
            };
            let program = match finding.token_program {
                ProgramKind::SplToken => "SPL",
                ProgramKind::Token2022 => "T22",
            };
            let authority = if finding.allowlisted {
                "allowlisted"
            } else if finding.zero_allowance {
                "zero allowance"
            } else {
                "unknown"
            };
            let state = match finding.token_state {
                AccountState::Initialized => "initialized",
                AccountState::Frozen => "frozen",
            };
            let asset = if finding.wrapped_native {
                ", wrapped SOL"
            } else if finding.nft_like {
                ", NFT-like"
            } else {
                ""
            };
            let _ = writeln!(
                output,
                "{risk} {program} {} mint {}: delegate {} ({authority}), {state}, balance {}, allowance {}, immediate {}, dormant {}{asset}.",
                short_address(finding.token_account),
                short_address(finding.mint),
                short_address(finding.delegate),
                finding.balance,
                finding.allowance,
                finding.immediate_exposure,
                finding.dormant_allowance,
            );
        }
        if self.findings_omitted > 0 {
            let _ = writeln!(
                output,
                "{} additional finding(s) omitted.",
                self.findings_omitted
            );
        }
        let _ = write!(
            output,
            "Authority fingerprint: {}. Review and revoke unknown delegates in a trusted wallet; no transaction was created or submitted.",
            self.authority_fingerprint
        );
        if output.len() <= MAX_OUTPUT_BYTES {
            return output;
        }

        format!(
            "{} — {} active token delegate(s); {} red, {} amber; detailed output exceeded the local bound. Finalized slots {}–{}. Authority fingerprint: {}. No transaction was created or submitted.",
            self.status.to_ascii_uppercase(),
            self.delegated_accounts,
            self.risk_counts.red,
            self.risk_counts.amber,
            self.snapshot_slots.minimum,
            self.snapshot_slots.maximum,
            self.authority_fingerprint
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditError {
    Rpc(RpcError),
    WrongCluster,
    AccountLimitExceeded,
    DuplicateAccount,
}

impl AuditError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Rpc(error) => error.code(),
            Self::WrongCluster => "CLUSTER_GENESIS_HASH_MISMATCH",
            Self::AccountLimitExceeded => "ACCOUNT_LIMIT_EXCEEDED",
            Self::DuplicateAccount => "ACCOUNT_DUPLICATE_ACROSS_PROGRAMS",
        }
    }
}

pub fn run_audit<T: HttpTransport>(
    config: &SentinelConfig,
    transport: &T,
) -> Result<AuditReport, AuditError> {
    let genesis_hash = fetch_genesis_hash(config, transport).map_err(AuditError::Rpc)?;
    if genesis_hash != config.expected_genesis_hash {
        return Err(AuditError::WrongCluster);
    }

    let classic = fetch_token_accounts(
        config,
        transport,
        ProgramKind::SplToken,
        2,
        None,
        config.max_accounts,
    )
    .map_err(AuditError::Rpc)?;
    let remaining_accounts = config.max_accounts.saturating_sub(classic.accounts.len());
    let token_2022 = fetch_token_accounts(
        config,
        transport,
        ProgramKind::Token2022,
        3,
        Some(classic.slot),
        remaining_accounts,
    )
    .map_err(AuditError::Rpc)?;
    if classic
        .accounts
        .len()
        .saturating_add(token_2022.accounts.len())
        > config.max_accounts
    {
        return Err(AuditError::AccountLimitExceeded);
    }
    let mut accounts = classic.accounts;
    accounts.extend(token_2022.accounts);
    accounts.sort_by_key(|account| account.address);
    if accounts
        .windows(2)
        .any(|pair| pair[0].address == pair[1].address)
    {
        return Err(AuditError::DuplicateAccount);
    }

    let account_snapshot_max = classic.slot.max(token_2022.slot);
    let mint_batch =
        fetch_mints(config, transport, &accounts, account_snapshot_max).map_err(AuditError::Rpc)?;
    let mut slots = vec![classic.slot, token_2022.slot];
    slots.extend(mint_batch.slots);
    let minimum = slots.iter().copied().min().unwrap_or(account_snapshot_max);
    let maximum = slots.iter().copied().max().unwrap_or(account_snapshot_max);

    Ok(classify(
        config.owner,
        genesis_hash,
        SnapshotSlots { minimum, maximum },
        &accounts,
        &mint_batch.mints,
        &config.allowed_delegates,
        config.max_findings,
    ))
}

pub fn classify(
    owner: Address,
    genesis_hash: Address,
    snapshot_slots: SnapshotSlots,
    accounts: &[TokenAccount],
    mints: &BTreeMap<(ProgramKind, Address), Option<MintAccount>>,
    allowed_delegates: &BTreeSet<Address>,
    max_findings: usize,
) -> AuditReport {
    let mut all_findings = Vec::new();
    for account in accounts {
        let Some(delegate) = account.delegate else {
            continue;
        };
        let mint = mints
            .get(&(account.program, account.mint))
            .and_then(Option::as_ref);
        let decimals = mint.map(|mint| mint.decimals);
        let immediate = account.amount.min(account.delegated_amount);
        let dormant = account.delegated_amount.saturating_sub(immediate);
        let allowlisted = allowed_delegates.contains(&delegate);
        let risk = if account.delegated_amount > 0 && !allowlisted {
            Risk::Red
        } else {
            Risk::Amber
        };
        all_findings.push(Finding {
            risk,
            token_account: account.address,
            token_program: account.program,
            mint: account.mint,
            delegate,
            token_state: account.state,
            balance: format_amount(account.amount, decimals),
            allowance: format_amount(account.delegated_amount, decimals),
            immediate_exposure: format_amount(immediate, decimals),
            dormant_allowance: format_amount(dormant, decimals),
            mint_decimals: decimals,
            allowlisted,
            zero_allowance: account.delegated_amount == 0,
            wrapped_native: account.is_native,
            nft_like: mint
                .is_some_and(|mint| mint.decimals == 0 && mint.supply == 1 && account.amount == 1),
            immediate_exposure_base_units: immediate,
        });
    }

    all_findings.sort_by(|left, right| {
        risk_rank(right.risk)
            .cmp(&risk_rank(left.risk))
            .then_with(|| {
                right
                    .immediate_exposure_base_units
                    .cmp(&left.immediate_exposure_base_units)
            })
            .then_with(|| left.token_account.cmp(&right.token_account))
    });
    let red = all_findings
        .iter()
        .filter(|finding| finding.risk == Risk::Red)
        .count();
    let amber = all_findings.len() - red;
    let authority_fingerprint = fingerprint(owner, genesis_hash, accounts);
    let delegated_accounts = all_findings.len();
    let findings_omitted = delegated_accounts.saturating_sub(max_findings);
    all_findings.truncate(max_findings);

    AuditReport {
        status: if red > 0 {
            "red"
        } else if amber > 0 {
            "amber"
        } else {
            "green"
        },
        owner,
        genesis_hash,
        snapshot_slots,
        accounts_scanned: accounts.len(),
        delegated_accounts,
        risk_counts: RiskCounts { red, amber },
        authority_fingerprint,
        findings: all_findings,
        findings_omitted,
        transaction_created: false,
        transaction_submitted: false,
    }
}

fn risk_rank(risk: Risk) -> u8 {
    match risk {
        Risk::Amber => 1,
        Risk::Red => 2,
    }
}

fn format_amount(value: u64, decimals: Option<u8>) -> String {
    let Some(decimals) = decimals else {
        return format!("{value} base units");
    };
    if decimals == 0 {
        return value.to_string();
    }
    let digits = value.to_string();
    let decimals = usize::from(decimals);
    let mut rendered = if digits.len() <= decimals {
        format!("0.{}{}", "0".repeat(decimals - digits.len()), digits)
    } else {
        let split = digits.len() - decimals;
        format!("{}.{}", &digits[..split], &digits[split..])
    };
    while rendered.ends_with('0') {
        rendered.pop();
    }
    if rendered.ends_with('.') {
        rendered.pop();
    }
    rendered
}

fn fingerprint(owner: Address, genesis_hash: Address, accounts: &[TokenAccount]) -> String {
    let mut records: Vec<String> = accounts
        .iter()
        .filter_map(|account| {
            account.delegate.map(|delegate| {
                let state = match account.state {
                    AccountState::Initialized => "initialized",
                    AccountState::Frozen => "frozen",
                };
                format!(
                    "{}|{}|{}|{}|{}|{}",
                    account.program.program_id(),
                    account.address,
                    account.mint,
                    delegate,
                    account.delegated_amount,
                    state
                )
            })
        })
        .collect();
    records.sort();
    let canonical = format!(
        "genesis={genesis_hash}\nowner={owner}\n{}",
        records.join("\n")
    );
    let digest = Sha256::digest(canonical.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn short_address(address: Address) -> String {
    let value = address.to_string();
    format!("{}…{}", &value[..4], &value[value.len() - 4..])
}
