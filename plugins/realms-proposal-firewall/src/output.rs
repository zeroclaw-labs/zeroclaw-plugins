use serde::{Deserialize, Serialize};

/// Maximum number of UTF-8 bytes returned by [`Report::to_json`].
pub const MAX_REPORT_JSON_BYTES: usize = 32 * 1024;
pub const MAX_EVIDENCE_CHARS: usize = 384;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Incomplete,
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    fn sort_rank(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct InstructionLocation {
    pub option_index: u8,
    pub transaction_index: u16,
    pub instruction_index: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<InstructionLocation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UnknownInstruction {
    pub program_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
    pub location: InstructionLocation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProposalSummary {
    pub address: String,
    pub state: String,
    pub governance: String,
    pub realm: String,
    pub threshold_percent: Option<u8>,
    pub hold_up_seconds: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voting_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voting_completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executing_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_vote_weight: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_vote_weight: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abstain_vote_weight: Option<String>,
    pub veto_vote_weight: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voting_deadline: Option<String>,
    pub analyzed_options: Vec<u8>,
    pub options: Vec<ProposalOptionSummary>,
    pub transactions: Vec<ProposalTransactionSummary>,
    pub transaction_count: String,
    pub instruction_count: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProposalTransactionSummary {
    pub address: String,
    pub option_index: u8,
    pub transaction_index: u16,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProposalOptionSummary {
    pub option_index: u8,
    pub vote_weight: String,
    pub result: String,
    pub transactions_executed: String,
    pub transactions_present: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Report {
    pub verdict: Verdict,
    pub complete: bool,
    pub proposal: ProposalSummary,
    pub findings: Vec<Finding>,
    pub unknown_instructions: Vec<UnknownInstruction>,
    pub evidence_slot: String,
    pub links: Vec<String>,
}

impl Report {
    pub fn canonicalize(&mut self) {
        for finding in &mut self.findings {
            finding.evidence = bounded_text(&finding.evidence, MAX_EVIDENCE_CHARS);
        }
        self.findings.sort_by(|left, right| {
            left.severity
                .sort_rank()
                .cmp(&right.severity.sort_rank())
                .then_with(|| left.code.cmp(&right.code))
                .then_with(|| left.location.cmp(&right.location))
                .then_with(|| left.evidence.cmp(&right.evidence))
        });
        self.unknown_instructions.sort_by(|left, right| {
            left.location
                .cmp(&right.location)
                .then_with(|| left.program_id.cmp(&right.program_id))
                .then_with(|| left.tag.cmp(&right.tag))
        });
        self.proposal.analyzed_options.sort_unstable();
        self.proposal.analyzed_options.dedup();
        self.links.sort();
        self.links.dedup();
        self.verdict = verdict(self.complete, &self.findings, &self.unknown_instructions);
    }

    /// Serializes a canonical report. Oversized output is replaced by a small,
    /// explicitly incomplete report rather than silently dropping findings.
    pub fn to_json(&self) -> String {
        let mut canonical = self.clone();
        canonical.canonicalize();
        if let Ok(json) = serde_json::to_string(&canonical) {
            if json.len() <= MAX_REPORT_JSON_BYTES {
                return json;
            }
        }

        let mut bounded = Report {
            verdict: Verdict::Incomplete,
            complete: false,
            proposal: canonical.proposal,
            findings: vec![Finding {
                code: "OUTPUT_LIMIT_EXCEEDED".to_owned(),
                severity: Severity::Critical,
                evidence:
                    "The deterministic report exceeded the output limit; review is incomplete"
                        .to_owned(),
                location: None,
            }],
            unknown_instructions: Vec::new(),
            evidence_slot: canonical.evidence_slot,
            links: canonical.links.into_iter().take(1).collect(),
        };
        bounded.canonicalize();
        serde_json::to_string(&bounded).unwrap_or_else(|_| {
            "{\"verdict\":\"INCOMPLETE\",\"complete\":false,\"findings\":[{\"code\":\"OUTPUT_SERIALIZATION_FAILED\",\"severity\":\"CRITICAL\",\"evidence\":\"Report serialization failed\"}]}".to_owned()
        })
    }
}

pub fn bounded_text(value: &str, maximum_chars: usize) -> String {
    let mut output = String::new();
    for character in value.chars().take(maximum_chars) {
        if character.is_control() {
            output.push(' ');
        } else {
            output.push(character);
        }
    }
    if value.chars().count() > maximum_chars {
        output.push_str("...");
    }
    output
}

fn verdict(
    complete: bool,
    findings: &[Finding],
    unknown_instructions: &[UnknownInstruction],
) -> Verdict {
    if !complete {
        return Verdict::Incomplete;
    }
    if !unknown_instructions.is_empty()
        || findings
            .iter()
            .any(|finding| finding.severity == Severity::Critical)
    {
        Verdict::Critical
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::High)
    {
        Verdict::High
    } else if findings
        .iter()
        .any(|finding| finding.severity == Severity::Medium)
    {
        Verdict::Medium
    } else {
        Verdict::Low
    }
}
