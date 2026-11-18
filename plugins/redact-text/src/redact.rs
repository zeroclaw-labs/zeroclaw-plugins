//! Pure redaction core. No wit-bindgen or wasm dependency so it compiles and
//! tests on the host with a plain `cargo test`, while the wasm component reuses
//! the exact same logic through `lib.rs`.

use serde::Deserialize;
use serde_json::Value;

pub const DEFAULT_REPLACEMENT: &str = "[REDACTED]";

/// Redaction policy resolved from this plugin's own config section.
///
/// The host validates the operator's values against `[config_schema]` in
/// `manifest.toml` and injects them as a *typed* JSON object, so these are real
/// Rust types and there is nothing left for the guest to string-parse. Operator
/// storage is still a string map; the schema is what tells the host to read
/// `false` as a boolean and `["a","b"]` as an array before the guest sees them.
///
/// Every schema property is optional, so every field has a default here. That
/// is the same reason a withheld `config_read` grant is safe: the host then
/// validates and injects `{}`, which yields exactly [`RedactConfig::default`].
///
/// Deliberately not `deny_unknown_fields`: `additionalProperties = false` in
/// the manifest already rejects undeclared operator keys before the guest runs,
/// so guest-side strictness would add no protection and would turn a
/// forward-compatible schema addition into a hard failure.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct RedactConfig {
    pub replacement: String,
    pub redact_emails: bool,
    pub patterns: Vec<String>,
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            replacement: DEFAULT_REPLACEMENT.to_string(),
            redact_emails: true,
            patterns: Vec::new(),
        }
    }
}

impl RedactConfig {
    /// Deserialize the typed `__config` object the host injects.
    ///
    /// A malformed object is reported, never swallowed. Falling back to the
    /// default policy would silently drop the operator's `patterns` list and
    /// under-redact, which is the one failure mode this plugin must not have.
    /// An absent `__config` (JSON null) is not malformed: it is a host that
    /// injected nothing, and defaults are the correct policy for it.
    ///
    /// The error is a pre-sanitized `String` rather than `serde_json::Error` so
    /// that a caller cannot leak a config value by formatting it; see
    /// [`describe_error`].
    pub fn from_json(config: &Value) -> Result<Self, String> {
        if config.is_null() {
            return Ok(Self::default());
        }
        serde_json::from_value::<Self>(config.clone())
            .map(Self::normalized)
            .map_err(|error| describe_error(&error))
    }

    /// Re-assert the guest-side invariants that `config_schema` also encodes.
    ///
    /// The schema rejects an empty `replacement` and empty `patterns` entries,
    /// but this runs whether or not a schema-enforcing host was in play. The
    /// empty-pattern filter in particular is load-bearing, not tidiness: `""`
    /// matches at every character boundary, so one empty pattern would rewrite
    /// the entire input into replacement markers.
    fn normalized(mut self) -> Self {
        if self.replacement.is_empty() {
            self.replacement = DEFAULT_REPLACEMENT.to_string();
        }
        self.patterns.retain(|pattern| !pattern.is_empty());
        self
    }
}

/// Describe a config deserialization failure without quoting the value that
/// caused it.
///
/// `serde_json::Error`'s `Display` embeds the offending value ("invalid type:
/// boolean `false`"). Config values are secret-marked by the host, and this
/// plugin's `patterns` are themselves the sensitive strings an operator wants
/// scrubbed, so echoing one into a `ToolResult` would hand it straight back to
/// the model. The category and position are enough to debug the only thing that
/// can produce this error once the host validates against `config_schema`: a
/// manifest/guest mismatch.
fn describe_error(error: &serde_json::Error) -> String {
    format!(
        "{:?} error at line {} column {}",
        error.classify(),
        error.line(),
        error.column()
    )
}

/// Apply email masking, bearer/API-token masking, and configured literal
/// patterns. Returns the scrubbed text and the number of redactions made. The
/// matched secret values are never logged or returned in the count.
pub fn redact(text: &str, cfg: &RedactConfig) -> (String, usize) {
    let mut out = text.to_string();
    let mut count = 0usize;

    if cfg.redact_emails {
        let (replaced, n) = mask_emails(&out, &cfg.replacement);
        out = replaced;
        count += n;
    }

    let (replaced, n) = mask_tokens(&out, &cfg.replacement);
    out = replaced;
    count += n;

    for pat in &cfg.patterns {
        let occurrences = out.matches(pat.as_str()).count();
        if occurrences > 0 {
            out = out.replace(pat.as_str(), &cfg.replacement);
            count += occurrences;
        }
    }

    (out, count)
}

fn mask_emails(text: &str, replacement: &str) -> (String, usize) {
    let mut result = String::with_capacity(text.len());
    let mut count = 0usize;
    for token in split_keep_delims(text) {
        if is_email(token) {
            result.push_str(replacement);
            count += 1;
        } else {
            result.push_str(token);
        }
    }
    (result, count)
}

fn mask_tokens(text: &str, replacement: &str) -> (String, usize) {
    let mut result = String::with_capacity(text.len());
    let mut count = 0usize;
    for token in split_keep_delims(text) {
        if is_secret_token(token) {
            result.push_str(replacement);
            count += 1;
        } else {
            result.push_str(token);
        }
    }
    (result, count)
}

fn is_email(token: &str) -> bool {
    let at = match token.find('@') {
        Some(i) => i,
        None => return false,
    };
    let (local, domain_with_at) = token.split_at(at);
    let domain = &domain_with_at[1..];
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
}

fn is_secret_token(token: &str) -> bool {
    const PREFIXES: [&str; 4] = ["sk-", "ghp_", "AKIA", "xoxb-"];
    if PREFIXES.iter().any(|p| token.starts_with(p)) && token.len() >= 8 {
        return true;
    }
    if token.len() >= 20 {
        let alnum = token.chars().all(|c| c.is_ascii_alphanumeric());
        let has_digit = token.chars().any(|c| c.is_ascii_digit());
        let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
        return alnum && has_digit && has_alpha;
    }
    false
}

/// Split into alternating word / delimiter chunks, preserving every character
/// so the rejoined output is byte-identical except at redacted spans.
fn split_keep_delims(text: &str) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut in_word = false;
    for (i, c) in text.char_indices() {
        let is_word = c.is_ascii_alphanumeric() || "@._%+-".contains(c);
        if i == 0 {
            in_word = is_word;
            continue;
        }
        if is_word != in_word {
            chunks.push(&text[start..i]);
            start = i;
            in_word = is_word;
        }
    }
    if start < text.len() {
        chunks.push(&text[start..]);
    }
    chunks
}
