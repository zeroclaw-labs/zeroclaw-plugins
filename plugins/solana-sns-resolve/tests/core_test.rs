
use solana_sns_resolve::core::resolve::resolve_domain;

const OK_RESP: &str = r#"{"s":"ok","result":"7xKmNabcdefghijklmnopqrstuvwxyz123456789AB"}"#;
const ERR_RESP: &str = r#"{"s":"error","result":"Domain not found"}"#;

#[test]
fn resolves_dot_sol() {
    let addr = resolve_domain("levrone.sol", |_url| Ok(OK_RESP.to_string()));
    assert!(addr.is_ok());
    assert_eq!(addr.unwrap(), "7xKmNabcdefghijklmnopqrstuvwxyz123456789AB");
}

#[test]
fn resolves_without_suffix() {
    let addr = resolve_domain("levrone", |_url| Ok(OK_RESP.to_string()));
    assert!(addr.is_ok());
}

#[test]
fn not_found_returns_error() {
    let addr = resolve_domain("notexist.sol", |_url| Ok(ERR_RESP.to_string()));
    assert!(addr.is_err());
    assert!(addr.unwrap_err().contains("not found"));
}

#[test]
fn empty_domain_rejected() {
    let addr = resolve_domain("", |_url| Ok(OK_RESP.to_string()));
    assert!(addr.is_err());
}

#[test]
fn network_error_returns_error() {
    let addr = resolve_domain("levrone.sol", |_url| Err("connection refused".to_string()));
    assert!(addr.is_err());
}

#[test]
fn strips_sol_suffix_in_url() {
    let mut called_url = String::new();
    let _ = resolve_domain("levrone.sol", |url| {
        called_url = url.to_string();
        Ok(OK_RESP.to_string())
    });
    assert!(called_url.ends_with("/levrone"), "URL should strip .sol: {}", called_url);
}
