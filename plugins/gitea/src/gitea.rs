//! Pure Gitea/Forgejo REST logic — no wasm, no HTTP, no host deps.
//!
//! This is the `rlib` half of the plugin: it parses the channel config, maps a
//! Gitea notification's latest comment (a `GiteaComment` JSON) onto the fields
//! the host's inbound message needs, decides admissibility (self/bot/mention
//! gating), builds the create-comment request body, and does the RFC3339 <-> Unix
//! time math for the poll cursor. The `#[cfg(target_family = "wasm")]` component
//! shim in `lib.rs` does only the I/O (waki HTTP calls with a `token` credential)
//! and reuses this logic verbatim, so the interesting behavior is covered by a
//! plain host `cargo test`.
//!
//! Scope: text issue/PR *conversation comments*. Inline PR review comments,
//! opening-post bodies without a comment, reactions, and media are deferred.

use serde::Deserialize;
use serde_json::{json, Value};

/// `User-Agent` for every request — some Gitea instances reject blank agents.
pub const GITEA_USER_AGENT: &str = "zeroclaw";

/// Conservative per-comment character cap. Gitea/Forgejo accept large bodies
/// (64k+); this floor leaves headroom for split markers and stays safe across
/// instances. Long agent replies are chunked into several comments.
pub const COMMENT_MAX_CHARS: usize = 60_000;

// ── config ────────────────────────────────────────────────────────────────

/// The plugin's config section. As a mirror this is the native `git` channel's
/// `[channels.git.<alias>]` (a serialized `GitConfig`); field names match the
/// native snake_case keys so the section can be fed verbatim. Only the fields
/// this plugin uses are declared — serde ignores the GitHub-only keys
/// (`app_id`, `private_key_path`, …), routing tables, and pacing.
#[derive(Debug, Clone, Deserialize)]
pub struct GiteaConfig {
    /// Forge provider selector. This plugin serves only `"gitea"`/`"forgejo"`;
    /// any other value (including the native default `"github"`) leaves it inert
    /// so a GitHub-intended section is never polled with Gitea endpoints.
    #[serde(default)]
    pub provider: String,
    /// Instance API base URL, including `/api/v1`, e.g.
    /// `https://git.example.org/api/v1`. Required — there is no default host,
    /// because every request carries the access token.
    #[serde(default)]
    pub api_base_url: Option<String>,
    /// Personal access token. Sent as `Authorization: token <token>`.
    #[serde(default)]
    pub access_token: String,
    /// Only deliver comments that @-mention the bot's own login. Default: true,
    /// matching the native channel.
    #[serde(default = "default_true")]
    pub mention_only: bool,
    /// Deliver comments authored by other bot accounts. The plugin's own
    /// comments are always dropped. Default: false.
    #[serde(default)]
    pub listen_to_bots: bool,
}

fn default_true() -> bool {
    true
}

impl Default for GiteaConfig {
    fn default() -> Self {
        Self {
            provider: String::new(),
            api_base_url: None,
            access_token: String::new(),
            mention_only: true,
            listen_to_bots: false,
        }
    }
}

impl GiteaConfig {
    /// Parse the JSON config string the host hands to `configure`. An empty or
    /// malformed string yields defaults (so a mis-permissioned `"{}"` is inert
    /// rather than a hard failure).
    pub fn from_json(config_json: &str) -> Self {
        serde_json::from_str(config_json).unwrap_or_default()
    }

    /// API base with any trailing slash trimmed, or `None` when blank.
    pub fn base_url(&self) -> Option<String> {
        self.api_base_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_end_matches('/').to_string())
    }

    /// The access token (trimmed), or `""` when unset.
    pub fn token(&self) -> &str {
        self.access_token.trim()
    }

    /// Whether `provider` selects this plugin's forge family.
    pub fn is_gitea(&self) -> bool {
        matches!(
            self.provider.trim().to_ascii_lowercase().as_str(),
            "gitea" | "forgejo"
        )
    }

    /// Fully configured: right provider, a base URL, and a token. The shim
    /// makes no network call unless this holds.
    pub fn is_active(&self) -> bool {
        self.is_gitea() && self.base_url().is_some() && !self.token().is_empty()
    }
}

// ── identifiers ───────────────────────────────────────────────────────────

/// A repository reference (`owner/repo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRef {
    pub owner: String,
    pub repo: String,
}

impl RepoRef {
    /// Parse `owner/repo`. `None` when either half is empty or `repo` has a `/`.
    pub fn parse(s: &str) -> Option<Self> {
        let (owner, repo) = s.trim().split_once('/')?;
        if owner.is_empty() || repo.is_empty() || repo.contains('/') {
            return None;
        }
        Some(Self {
            owner: owner.to_string(),
            repo: repo.to_string(),
        })
    }
}

impl std::fmt::Display for RepoRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.repo)
    }
}

/// An issue or pull-request reference (`owner/repo#number`) — the channel's
/// `reply_target` / `recipient` wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRef {
    pub repo: RepoRef,
    pub number: u64,
}

impl IssueRef {
    /// Parse `owner/repo#number`.
    pub fn parse(s: &str) -> Option<Self> {
        let (repo, number) = s.trim().split_once('#')?;
        Some(Self {
            repo: RepoRef::parse(repo)?,
            number: number.parse().ok()?,
        })
    }
}

impl std::fmt::Display for IssueRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.repo, self.number)
    }
}

/// Recover the `owner/repo` from any Gitea API URL that contains a
/// `.../repos/{owner}/{repo}/...` path — works for both issue and comment URLs.
pub fn parse_repo_from_url(url: &str) -> Option<RepoRef> {
    let segs: Vec<&str> = url.split('/').filter(|s| !s.is_empty()).collect();
    let repos_pos = segs.iter().rposition(|&s| s == "repos")?;
    let owner = segs.get(repos_pos + 1)?;
    let repo = segs.get(repos_pos + 2)?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(RepoRef {
        owner: (*owner).to_string(),
        repo: (*repo).to_string(),
    })
}

/// Recover `(owner/repo, number)` from a Gitea issue/PR API URL of the form
/// `.../repos/{owner}/{repo}/issues/{n}` (also accepts `/pulls/{n}`). Used as a
/// fallback when a notification omits its `repository` object.
pub fn parse_issue_api_url(url: &str) -> Option<(RepoRef, u64)> {
    let repo = parse_repo_from_url(url)?;
    let segs: Vec<&str> = url.split('/').filter(|s| !s.is_empty()).collect();
    let repos_pos = segs.iter().rposition(|&s| s == "repos")?;
    let kind_pos = segs
        .iter()
        .skip(repos_pos + 3)
        .position(|&s| s == "issues" || s == "pulls")?
        + repos_pos
        + 3;
    let number: u64 = segs.get(kind_pos + 1)?.parse().ok()?;
    Some((repo, number))
}

// ── REST payloads ─────────────────────────────────────────────────────────

/// A Gitea user. The payload carries BOTH `login` and `username` (same value);
/// Forgejo/older builds may send only one, so keep them as separate optional
/// fields (an `alias` would make serde reject a response that has both).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GiteaUser {
    #[serde(default)]
    pub login: String,
    #[serde(default)]
    pub username: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub is_bot: bool,
}

impl GiteaUser {
    /// The effective login (prefers `login`, falls back to `username`).
    pub fn login(&self) -> String {
        if self.login.is_empty() {
            self.username.clone()
        } else {
            self.login.clone()
        }
    }

    /// Whether this account is a bot (explicit flag, `type == "Bot"`, or a
    /// `[bot]` login suffix).
    pub fn is_bot(&self) -> bool {
        self.is_bot || self.kind.eq_ignore_ascii_case("bot") || self.login().ends_with("[bot]")
    }
}

/// A Gitea issue/PR comment (`GET .../issues/comments/{id}`).
#[derive(Debug, Clone, Deserialize)]
pub struct GiteaComment {
    pub id: u64,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub user: GiteaUser,
    #[serde(default)]
    pub created_at: String,
    /// `.../api/v1/repos/{owner}/{repo}/issues/{number}` — the issue this
    /// comment belongs to.
    #[serde(default)]
    pub issue_url: String,
}

impl GiteaComment {
    /// The issue/PR number, parsed from the trailing segment of `issue_url`.
    pub fn issue_number(&self) -> Option<u64> {
        self.issue_url.rsplit('/').next()?.parse().ok()
    }
}

/// The `id` of a freshly created comment (`POST .../comments` response).
#[derive(Debug, Clone, Deserialize)]
pub struct CreatedComment {
    pub id: u64,
}

/// One entry of `GET /notifications`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NotificationThread {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub repository: Option<NotifRepo>,
    #[serde(default)]
    pub subject: Option<NotifSubject>,
    #[serde(default)]
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NotifRepo {
    #[serde(default)]
    pub full_name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NotifSubject {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub latest_comment_url: String,
    /// `"Issue"`, `"Pull"`, `"Commit"`, `"Repository"`.
    #[serde(default, rename = "type")]
    pub kind: String,
}

impl NotificationThread {
    /// The repository this notification targets, from its `repository` object
    /// when present, else recovered from the subject's comment/issue URL.
    pub fn repo(&self) -> Option<RepoRef> {
        self.repository
            .as_ref()
            .and_then(|r| RepoRef::parse(&r.full_name))
            .or_else(|| {
                let s = self.subject.as_ref()?;
                parse_repo_from_url(&s.latest_comment_url).or_else(|| parse_repo_from_url(&s.url))
            })
    }

    /// The comment URL to fetch, for an issue/PR subject that has one.
    pub fn comment_url(&self) -> Option<&str> {
        let s = self.subject.as_ref()?;
        if !matches!(s.kind.as_str(), "Issue" | "Pull") {
            return None;
        }
        let url = s.latest_comment_url.trim();
        (!url.is_empty()).then_some(url)
    }
}

// ── inbound mapping ───────────────────────────────────────────────────────

/// A comment mapped to the host inbound-message fields (the `channel` is stamped
/// by the host — `"git"` for a mirror, `"gitea"` for a novel plugin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub id: String,
    pub sender: String,
    pub reply_target: String,
    pub content: String,
    pub timestamp: u64,
}

/// Map a comment onto an [`Inbound`], mirroring the native `git` channel's
/// `from_comment` + `event_to_message`: id `ghc_<comment_id>`, sender = author
/// login, reply target = `owner/repo#number`, content = the comment body.
/// Returns `None` when the issue number can't be recovered.
pub fn comment_to_inbound(comment: &GiteaComment, repo: &RepoRef) -> Option<Inbound> {
    let number = comment.issue_number()?;
    let ts = rfc3339_to_unix(&comment.created_at).unwrap_or(0).max(0) as u64;
    Some(Inbound {
        id: format!("ghc_{}", comment.id),
        sender: comment.user.login(),
        reply_target: format!("{repo}#{number}"),
        content: comment.body.clone(),
        timestamp: ts,
    })
}

/// Whether a comment should be delivered to the agent. Author gating only —
/// time-cursor and dedup are the shim's stateful job:
///   - never the bot's own comment (`author == self_login`);
///   - other bots only when `listen_to_bots`;
///   - under `mention_only`, only comments that @-mention the bot's login (a
///     missing self-login fails closed — nothing is delivered).
pub fn should_admit(
    comment: &GiteaComment,
    self_login: &str,
    mention_only: bool,
    listen_to_bots: bool,
) -> bool {
    let author = comment.user.login();
    if !self_login.is_empty() && author.eq_ignore_ascii_case(self_login) {
        return false;
    }
    if comment.user.is_bot() && !listen_to_bots {
        return false;
    }
    if mention_only {
        if self_login.is_empty() {
            return false;
        }
        if !contains_mention(&comment.body, self_login) {
            return false;
        }
    }
    true
}

/// The bot's login from a `GET /user` response body.
pub fn parse_self_login(user: &Value) -> Option<String> {
    let u: GiteaUser = serde_json::from_value(user.clone()).ok()?;
    let login = u.login();
    (!login.is_empty()).then_some(login)
}

/// Case-insensitive `@handle` match on a word boundary, so `@mybot` does not
/// match `@mybot-helper`. ASCII folding: forge logins are ASCII.
pub fn contains_mention(body: &str, handle: &str) -> bool {
    if handle.is_empty() {
        return false;
    }
    let body_lower = body.to_ascii_lowercase();
    let needle = format!("@{}", handle.trim_start_matches('@').to_ascii_lowercase());
    let mut start = 0;
    while let Some(pos) = body_lower[start..].find(&needle) {
        let end = start + pos + needle.len();
        let boundary = body_lower[end..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '-' || c == '_'));
        if boundary {
            return true;
        }
        start = end;
    }
    false
}

// ── outbound ──────────────────────────────────────────────────────────────

/// Build the `POST .../issues/{n}/comments` request body.
pub fn build_comment_body(text: &str) -> Value {
    json!({ "body": text })
}

/// Split a long reply into comment-sized chunks, preferring line boundaries so a
/// reply longer than [`COMMENT_MAX_CHARS`] is posted as several comments rather
/// than rejected. A single over-long line is hard-split by characters.
pub fn chunk_text(text: &str, max: usize) -> Vec<String> {
    if text.chars().count() <= max {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    for line in text.split_inclusive('\n') {
        if current.chars().count() + line.chars().count() > max && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
        }
        if line.chars().count() > max {
            let mut buf = String::new();
            for ch in line.chars() {
                if buf.chars().count() + 1 > max {
                    chunks.push(std::mem::take(&mut buf));
                }
                buf.push(ch);
            }
            current.push_str(&buf);
        } else {
            current.push_str(line);
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

// ── endpoint URLs ─────────────────────────────────────────────────────────

/// `GET /notifications?all=false&since=<rfc3339>` — the unread-notifications
/// poll. `since` filters by the notification's update time.
pub fn notifications_url(base: &str, since_rfc3339: &str) -> String {
    format!(
        "{}/notifications?all=false&since={}",
        base.trim_end_matches('/'),
        encode_query_value(since_rfc3339)
    )
}

/// `POST /repos/{owner}/{repo}/issues/{number}/comments` — create a comment.
pub fn create_comment_url(base: &str, repo: &RepoRef, number: u64) -> String {
    format!(
        "{}/repos/{}/{}/issues/{}/comments",
        base.trim_end_matches('/'),
        repo.owner,
        repo.repo,
        number
    )
}

/// `GET /user` — the bot-identity endpoint.
pub fn user_url(base: &str) -> String {
    format!("{}/user", base.trim_end_matches('/'))
}

/// Percent-encode the characters of an RFC3339 timestamp that are unsafe in a
/// query value (`:` and `+`). Everything else in an RFC3339 UTC string is
/// query-safe.
fn encode_query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            ':' => out.push_str("%3A"),
            '+' => out.push_str("%2B"),
            other => out.push(other),
        }
    }
    out
}

// ── RFC3339 <-> Unix seconds (UTC) ────────────────────────────────────────
//
// Hand-rolled (no chrono) so the pure core stays dependency-free and the wasm
// build has no clock/date backend to worry about. Uses Howard Hinnant's
// days-from-civil algorithm.

/// Days since 1970-01-01 for a proleptic-Gregorian `y-m-d`.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp as i64 + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`]: `(year, month, day)` for a day count.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format Unix seconds (UTC) as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn unix_to_rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Parse an RFC3339 timestamp to Unix seconds (UTC). Accepts a trailing `Z`, a
/// `±hh:mm`/`±hhmm` offset, and an optional fractional-seconds part (ignored).
pub fn rfc3339_to_unix(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let mut ts = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec;

    let mut rest = &s[19..];
    if let Some(stripped) = rest.strip_prefix('.') {
        let non_digit = stripped
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(stripped.len());
        rest = &stripped[non_digit..];
    }
    match rest.chars().next() {
        None | Some('Z') | Some('z') => {}
        Some('+') | Some('-') => {
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            let tz = &rest[1..];
            let oh: i64 = tz.get(0..2)?.parse().ok()?;
            let om: i64 = if tz.len() >= 5 && tz.as_bytes().get(2) == Some(&b':') {
                tz.get(3..5)?.parse().ok()?
            } else if tz.len() >= 4 {
                tz.get(2..4)?.parse().ok()?
            } else {
                0
            };
            ts -= sign * (oh * 3600 + om * 60);
        }
        _ => return None,
    }
    Some(ts)
}

/// The path of a request URL, without scheme, host, query or fragment. Error
/// messages reach host logs, so they name the request this way rather than by
/// the operator's server address or query parameters.
pub fn url_path(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let tail = &rest[rest.find(['/', '?', '#']).unwrap_or(rest.len())..];
    if !tail.starts_with('/') {
        return "/";
    }
    tail.split(['?', '#']).next().unwrap_or("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── config ──
    #[test]
    fn config_parses_native_git_section_fields() {
        let json = r#"{
            "enabled": true,
            "provider": "gitea",
            "app_id": 0,
            "private_key_path": "",
            "api_base_url": "https://git.example.org/api/v1/",
            "access_token": "  tok123  ",
            "mention_only": false,
            "listen_to_bots": true,
            "repos": ["a/b"],
            "events": {}
        }"#;
        let cfg = GiteaConfig::from_json(json);
        assert_eq!(
            cfg.base_url().as_deref(),
            Some("https://git.example.org/api/v1")
        );
        assert_eq!(cfg.token(), "tok123");
        assert!(cfg.is_gitea());
        assert!(cfg.is_active());
        assert!(!cfg.mention_only);
        assert!(cfg.listen_to_bots);
    }

    #[test]
    fn config_defaults_mention_only_true_and_is_inert_when_empty() {
        let cfg = GiteaConfig::from_json("{}");
        assert!(cfg.mention_only, "mention_only defaults to true");
        assert!(!cfg.is_active());
        // Malformed JSON also yields inert defaults.
        assert!(!GiteaConfig::from_json("not json").is_active());
    }

    #[test]
    fn config_forgejo_is_gitea_but_github_and_blank_are_not() {
        let mk = |p: &str| GiteaConfig {
            provider: p.to_string(),
            api_base_url: Some("https://h/api/v1".into()),
            access_token: "t".into(),
            ..Default::default()
        };
        assert!(mk("forgejo").is_active());
        assert!(mk("GITEA").is_active());
        assert!(!mk("github").is_active(), "github section must stay inert");
        assert!(
            !mk("").is_active(),
            "blank provider (native default github) is inert"
        );
    }

    #[test]
    fn config_inactive_without_base_or_token() {
        let no_base = GiteaConfig {
            provider: "gitea".into(),
            access_token: "t".into(),
            ..Default::default()
        };
        assert!(!no_base.is_active());
        let no_token = GiteaConfig {
            provider: "gitea".into(),
            api_base_url: Some("https://h/api/v1".into()),
            access_token: "   ".into(),
            ..Default::default()
        };
        assert!(!no_token.is_active());
    }

    // ── identifiers ──
    #[test]
    fn repo_ref_round_trips_and_rejects_malformed() {
        let r = RepoRef::parse("octo/repo").unwrap();
        assert_eq!(r.owner, "octo");
        assert_eq!(r.to_string(), "octo/repo");
        assert!(RepoRef::parse("no-slash").is_none());
        assert!(RepoRef::parse("/repo").is_none());
        assert!(RepoRef::parse("owner/").is_none());
        assert!(RepoRef::parse("a/b/c").is_none());
    }

    #[test]
    fn issue_ref_round_trips_and_rejects_bad_number() {
        let i = IssueRef::parse("octo/repo#42").unwrap();
        assert_eq!(i.number, 42);
        assert_eq!(i.repo.owner, "octo");
        assert_eq!(i.to_string(), "octo/repo#42");
        assert!(IssueRef::parse("octo/repo").is_none());
        assert!(IssueRef::parse("octo/repo#abc").is_none());
        assert!(IssueRef::parse("bad#1").is_none());
    }

    #[test]
    fn parse_issue_api_url_extracts_repo_and_number() {
        let (r, n) =
            parse_issue_api_url("https://git.example.org/api/v1/repos/forge/project/issues/7")
                .unwrap();
        assert_eq!(r.to_string(), "forge/project");
        assert_eq!(n, 7);
        // Pull URLs work too.
        let (r2, n2) = parse_issue_api_url("https://h/api/v1/repos/o/r/pulls/12").unwrap();
        assert_eq!(r2.to_string(), "o/r");
        assert_eq!(n2, 12);
        assert!(parse_issue_api_url("https://h/api/v1/repos/o/r").is_none());
    }

    // ── payloads / mapping ──
    #[test]
    fn gitea_user_accepts_both_login_and_username() {
        let both: GiteaUser =
            serde_json::from_str(r#"{"id":6,"login":"botbot","username":"botbot"}"#).unwrap();
        assert_eq!(both.login(), "botbot");
        let only_username: GiteaUser = serde_json::from_str(r#"{"username":"solo"}"#).unwrap();
        assert_eq!(only_username.login(), "solo");
    }

    #[test]
    fn gitea_user_bot_detection() {
        let flag: GiteaUser = serde_json::from_str(r#"{"login":"x","is_bot":true}"#).unwrap();
        assert!(flag.is_bot());
        let typ: GiteaUser = serde_json::from_str(r#"{"login":"x","type":"Bot"}"#).unwrap();
        assert!(typ.is_bot());
        let suffix: GiteaUser = serde_json::from_str(r#"{"login":"ci[bot]"}"#).unwrap();
        assert!(suffix.is_bot());
        let human: GiteaUser = serde_json::from_str(r#"{"login":"alice"}"#).unwrap();
        assert!(!human.is_bot());
    }

    #[test]
    fn comment_extracts_issue_number_and_maps_to_inbound() {
        let comment: GiteaComment = serde_json::from_value(serde_json::json!({
            "id": 99,
            "body": "@bot hello",
            "user": {"login": "alice"},
            "created_at": "2026-06-13T01:05:00Z",
            "issue_url": "https://forgejo.example/api/v1/repos/forge/project/issues/7"
        }))
        .unwrap();
        assert_eq!(comment.issue_number(), Some(7));
        let repo = RepoRef::parse("forge/project").unwrap();
        let inb = comment_to_inbound(&comment, &repo).unwrap();
        assert_eq!(inb.id, "ghc_99");
        assert_eq!(inb.sender, "alice");
        assert_eq!(inb.reply_target, "forge/project#7");
        assert_eq!(inb.content, "@bot hello");
        assert_eq!(
            inb.timestamp,
            rfc3339_to_unix("2026-06-13T01:05:00Z").unwrap() as u64
        );
    }

    // ── admissibility ──
    #[test]
    fn should_admit_drops_self_and_other_bots() {
        let mk = |login: &str, is_bot: bool, body: &str| GiteaComment {
            id: 1,
            body: body.to_string(),
            user: GiteaUser {
                login: login.to_string(),
                username: String::new(),
                kind: String::new(),
                is_bot,
            },
            created_at: "2026-06-13T01:05:00Z".into(),
            issue_url: "https://h/api/v1/repos/o/r/issues/1".into(),
        };
        // self comment dropped even with a mention.
        assert!(!should_admit(
            &mk("mybot", false, "@mybot hi"),
            "mybot",
            true,
            false
        ));
        // other bot dropped unless listen_to_bots.
        assert!(!should_admit(
            &mk("ci", true, "@mybot hi"),
            "mybot",
            true,
            false
        ));
        assert!(should_admit(
            &mk("ci", true, "@mybot hi"),
            "mybot",
            true,
            true
        ));
    }

    #[test]
    fn should_admit_honors_mention_gate() {
        let mk = |body: &str| GiteaComment {
            id: 1,
            body: body.to_string(),
            user: GiteaUser {
                login: "alice".into(),
                ..Default::default()
            },
            created_at: "2026-06-13T01:05:00Z".into(),
            issue_url: "https://h/api/v1/repos/o/r/issues/1".into(),
        };
        assert!(should_admit(&mk("@mybot please"), "mybot", true, false));
        assert!(!should_admit(&mk("no mention here"), "mybot", true, false));
        // mention_only off: any human comment passes.
        assert!(should_admit(&mk("no mention here"), "mybot", false, false));
        // mention_only on but self-login unknown: fail closed.
        assert!(!should_admit(&mk("@mybot please"), "", true, false));
    }

    #[test]
    fn contains_mention_is_word_boundaried_and_case_insensitive() {
        assert!(contains_mention("hey @MyBot look", "mybot"));
        assert!(contains_mention("@mybot", "mybot"));
        assert!(contains_mention("(@mybot)", "mybot"));
        assert!(!contains_mention("@mybot-helper hi", "mybot"));
        assert!(!contains_mention("email mybot@host", "mybot"));
        assert!(!contains_mention("nothing", ""));
        // handle passed with a leading @ is normalized.
        assert!(contains_mention("hi @mybot", "@mybot"));
    }

    // ── notifications ──
    #[test]
    fn notification_thread_resolves_repo_and_comment_url() {
        let th: NotificationThread = serde_json::from_value(serde_json::json!({
            "id": 5,
            "repository": {"full_name": "forge/project"},
            "subject": {
                "title": "Bug",
                "url": "https://h/api/v1/repos/forge/project/issues/7",
                "latest_comment_url": "https://h/api/v1/repos/forge/project/issues/comments/99",
                "type": "Issue"
            },
            "updated_at": "2026-06-13T01:05:00Z"
        }))
        .unwrap();
        assert_eq!(th.repo().unwrap().to_string(), "forge/project");
        assert_eq!(
            th.comment_url(),
            Some("https://h/api/v1/repos/forge/project/issues/comments/99")
        );
    }

    #[test]
    fn notification_repo_falls_back_to_subject_url() {
        let th: NotificationThread = serde_json::from_value(serde_json::json!({
            "subject": {
                "url": "https://h/api/v1/repos/o/r/issues/3",
                "latest_comment_url": "https://h/api/v1/repos/o/r/issues/comments/1",
                "type": "Pull"
            },
            "updated_at": "2026-06-13T01:05:00Z"
        }))
        .unwrap();
        assert_eq!(th.repo().unwrap().to_string(), "o/r");
        assert!(th.comment_url().is_some());
    }

    #[test]
    fn notification_skips_non_issue_subjects_and_empty_comment_url() {
        let commit: NotificationThread = serde_json::from_value(serde_json::json!({
            "subject": {"type": "Commit", "latest_comment_url": "https://h/x"}
        }))
        .unwrap();
        assert!(commit.comment_url().is_none());
        let no_comment: NotificationThread = serde_json::from_value(serde_json::json!({
            "subject": {"type": "Issue", "latest_comment_url": ""}
        }))
        .unwrap();
        assert!(no_comment.comment_url().is_none());
    }

    #[test]
    fn parse_self_login_reads_user_payload() {
        let v = serde_json::json!({"id": 1, "login": "mybot", "username": "mybot"});
        assert_eq!(parse_self_login(&v).as_deref(), Some("mybot"));
        assert!(parse_self_login(&serde_json::json!({})).is_none());
    }

    // ── outbound ──
    #[test]
    fn build_comment_body_wraps_text() {
        assert_eq!(build_comment_body("hi"), serde_json::json!({"body": "hi"}));
    }

    #[test]
    fn chunk_text_keeps_short_text_whole() {
        assert_eq!(chunk_text("hello", 100), vec!["hello".to_string()]);
    }

    #[test]
    fn chunk_text_splits_on_line_boundaries() {
        let text = "a".repeat(30) + "\n" + &"b".repeat(30);
        let chunks = chunk_text(&text, 40);
        assert!(chunks.len() >= 2);
        assert!(chunks.iter().all(|c| c.chars().count() <= 40));
        assert_eq!(
            chunks.concat().replace('\n', ""),
            "a".repeat(30) + &"b".repeat(30)
        );
    }

    #[test]
    fn chunk_text_hard_splits_an_overlong_line() {
        let text = "x".repeat(250);
        let chunks = chunk_text(&text, 100);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.chars().count() <= 100));
        assert_eq!(chunks.concat(), text);
    }

    // ── URLs ──
    #[test]
    fn notifications_url_encodes_since_colons() {
        let url = notifications_url("https://git.example.org/api/v1", "2026-07-10T12:00:00Z");
        assert_eq!(
            url,
            "https://git.example.org/api/v1/notifications?all=false&since=2026-07-10T12%3A00%3A00Z"
        );
    }

    #[test]
    fn create_comment_and_user_urls() {
        let repo = RepoRef::parse("o/r").unwrap();
        assert_eq!(
            create_comment_url("https://h/api/v1/", &repo, 7),
            "https://h/api/v1/repos/o/r/issues/7/comments"
        );
        assert_eq!(user_url("https://h/api/v1"), "https://h/api/v1/user");
    }

    // ── time ──
    #[test]
    fn rfc3339_epoch_and_known_dates() {
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(rfc3339_to_unix("2000-01-01T00:00:00Z"), Some(946_684_800));
        assert_eq!(unix_to_rfc3339(946_684_800), "2000-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_handles_offsets_and_fractional_seconds() {
        // +01:00 is one hour ahead → earlier Unix time.
        let z = rfc3339_to_unix("2026-06-13T01:05:00Z").unwrap();
        assert_eq!(rfc3339_to_unix("2026-06-13T02:05:00+01:00"), Some(z));
        assert_eq!(rfc3339_to_unix("2026-06-13T00:05:00-01:00"), Some(z));
        // Fractional seconds are ignored.
        assert_eq!(rfc3339_to_unix("2026-06-13T01:05:00.512Z"), Some(z));
        // Compact offset form.
        assert_eq!(rfc3339_to_unix("2026-06-13T02:05:00+0100"), Some(z));
    }

    #[test]
    fn rfc3339_round_trips_across_a_range() {
        for &secs in &[1i64, 1_000_000, 1_600_000_000, 1_781_658_300, 2_000_000_000] {
            let s = unix_to_rfc3339(secs);
            assert_eq!(rfc3339_to_unix(&s), Some(secs), "round trip {s}");
        }
    }

    #[test]
    fn rfc3339_rejects_garbage() {
        assert!(rfc3339_to_unix("nope").is_none());
        assert!(rfc3339_to_unix("2026-13-01T00:00:00Z").is_none());
        assert!(rfc3339_to_unix("").is_none());
    }
}
