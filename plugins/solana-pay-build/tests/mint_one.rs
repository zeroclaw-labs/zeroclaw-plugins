//! Mints one real request from the component, without a model in the loop.
//!
//! The co-sign flow has to be provable end to end even when a provider quota is
//! spent. What matters for the security claim is that the *component* mints the
//! reference and applies the limits — not which surface asked it to. This calls
//! the same `build_payment_request` the tool calls.
//!
//!   cargo test --test mint_one -- --nocapture

use solana_pay_build::pay::{build_payment_request, Charge, ShopConfig};

#[test]
fn mint_one_above_the_cosign_threshold() {
    let cfg = ShopConfig {
        recipient: "GsbwXfJraMomNxBcjK1LfJ8HPnzUnEzUcNvLYSbxNQpr".to_string(),
        allowed_tokens: vec!["SOL".to_string()],
        max_amount: "500".to_string(),
    };
    // 0.12 SOL — over the 0.1 co-sign threshold used for this run, under the
    // ceiling. The tier boundary is the policy layer's job; the component's job
    // is to refuse anything over the ceiling and mint a reference for the rest.
    let charge = Charge {
        label: "table-cosign".to_string(),
        amount: "0.12".to_string(),
        token: "SOL".to_string(),
    };
    let salt = format!("cosign-{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());

    let r = build_payment_request(&cfg, &charge, &salt).expect("component refused a valid charge");
    println!("URL={}", r.url);
    println!("REFERENCE={}", r.reference);
}
