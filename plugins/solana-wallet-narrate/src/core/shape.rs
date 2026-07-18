
pub fn format_narration(wallet: &str, sentences: &[String]) -> String {
    let short = if wallet.len() > 8 {
        format!("{}..{}", &wallet[..4], &wallet[wallet.len() - 4..])
    } else {
        wallet.to_string()
    };
    let mut parts = vec![format!("Recent activity for {}:", short)];
    for (i, s) in sentences.iter().enumerate() {
        parts.push(format!("{}. {}", i + 1, s));
    }
    parts.join("\n")
}
