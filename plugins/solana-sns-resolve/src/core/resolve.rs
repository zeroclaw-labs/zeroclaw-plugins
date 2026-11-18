
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SnsResponse {
    s: String,
    result: Option<String>,
}

pub fn resolve_domain(
    domain: &str,
    mut fetch: impl FnMut(&str) -> Result<String, String>,
) -> Result<String, String> {
    let name = domain.trim_end_matches(".sol").trim();
    if name.is_empty() {
        return Err("Empty domain name".to_string());
    }

    let url = format!("https://sns-sdk-proxy.bonfida.workers.dev/resolve/{}", name);
    let raw = fetch(&url)?;

    let resp: SnsResponse = serde_json::from_str(&raw)
        .map_err(|e| format!("parse error: {e}"))?;

    if resp.s != "ok" {
        return Err(format!("Domain not found or not registered: {}", domain));
    }

    resp.result.ok_or_else(|| format!("No address found for '{}'", domain))
}
