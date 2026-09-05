use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::address::Address;
use crate::config::{ExplorerCluster, SentinelConfig};
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
    #[serde(skip)]
    pub explorer_cluster: Option<ExplorerCluster>,
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
        let wallet = render_address(self.owner, self.explorer_cluster);
        if self.delegated_accounts == 0 {
            return format!(
                "🟢 **Overall risk: GREEN**\n\n**Wallet:** {wallet}\n**Accounts scanned:** `{}`\n**Finalized slots:** `{}–{}`\n\nNo SPL Token or Token-2022 account delegates were found.\n\n**Authority fingerprint**\n`{}`\n\n**Transaction status**\nNo transaction was created or submitted.",
                self.accounts_scanned,
                self.snapshot_slots.minimum,
                self.snapshot_slots.maximum,
                self.authority_fingerprint
            );
        }
        let status_icon = if self.status == "red" { "🔴" } else { "🟠" };
        let mut output = format!(
            "{status_icon} **Overall risk: {}**\n\n**Wallet:** {wallet}\n**Findings:** `{}` · **Finalized slots:** `{}–{}`\n",
            self.status.to_ascii_uppercase(),
            self.delegated_accounts,
            self.snapshot_slots.minimum,
            self.snapshot_slots.maximum
        );
        for (index, finding) in self.findings.iter().enumerate() {
            let risk = match finding.risk {
                Risk::Red => "RED",
                Risk::Amber => "AMBER",
            };
            let program = match finding.token_program {
                ProgramKind::SplToken => "SPL Token",
                ProgramKind::Token2022 => "Token-2022",
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
                " · wrapped SOL"
            } else if finding.nft_like {
                " · NFT-like"
            } else {
                ""
            };
            let _ = writeln!(
                output,
                "\n**{}. {risk} · {program}**\n- **Account:** {}\n- **Mint:** {}\n- **Delegate:** {} · {authority}\n- **State:** `{state}`{asset}\n- **Balance:** `{}` · **Allowance:** `{}`\n- **Exposure:** `{}` immediate · `{}` dormant",
                index + 1,
                render_address(finding.token_account, self.explorer_cluster),
                render_address(finding.mint, self.explorer_cluster),
                render_address(finding.delegate, self.explorer_cluster),
                finding.balance,
                finding.allowance,
                finding.immediate_exposure,
                finding.dormant_allowance,
            );
        }
        if self.findings_omitted > 0 {
            let _ = writeln!(
                output,
                "\n_{} additional finding(s) omitted; the fingerprint still covers all permissions._",
                self.findings_omitted
            );
        }
        let _ = write!(
            output,
            "\n**Authority fingerprint**\n`{}`\n\n**Transaction status**\nNo transaction was created or submitted.\n\n**Recommended action**\nReview and revoke unknown delegates in a trusted wallet.",
            self.authority_fingerprint,
        );
        if output.len() <= MAX_OUTPUT_BYTES {
            return output;
        }

        format!(
            "{status_icon} **Overall risk: {}**\n\n**Wallet:** {wallet}\n**Findings:** `{}` · `{}` red · `{}` amber\n**Finalized slots:** `{}–{}`\n\nDetailed findings exceeded the local output bound; the fingerprint still covers all permissions.\n\n**Authority fingerprint**\n`{}`\n\n**Transaction status**\nNo transaction was created or submitted.",
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

    let mut report = classify(
        config.owner,
        genesis_hash,
        SnapshotSlots { minimum, maximum },
        &accounts,
        &mint_batch.mints,
        &config.allowed_delegates,
        config.max_findings,
    );
    report.explorer_cluster = config.explorer_cluster;
    Ok(report)
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
        explorer_cluster: None,
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

fn render_address(address: Address, cluster: Option<ExplorerCluster>) -> String {
    let label = short_address(address);
    let Some(cluster) = cluster else {
        return format!("`{label}`");
    };
    format!(
        "[{label}](https://explorer.solana.com/address/{address}{})",
        cluster.explorer_query()
    )
}
