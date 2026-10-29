//! Negative controls: proof that the guards can fail.
//!
//! A passing test suite says the code did what it was asked. It does not say
//! the refusals are load-bearing — a guard that was accidentally deleted, or
//! whose condition was inverted, would leave every happy-path test green.
//!
//! So each control here does two things in one test: it plants the violation
//! and asserts the build refuses, *and* it asserts the same input passes once
//! the violation is removed. If a guard stops working, the first half fails. If
//! a test starts passing for the wrong reason — a typo in the fixture, a
//! recipient that was never valid — the second half fails. A check nobody has
//! watched fail is decoration.
//!
//! Run: cargo test --test negative_controls

use solana_pay_build::pay::{build_payment_request, Charge, ShopConfig};

/// A shop that accepts SOL and one mint, ceiling 500.
fn shop() -> ShopConfig {
    ShopConfig {
        recipient: "GsbwXfJraMomNxBcjK1LfJ8HPnzUnEzUcNvLYSbxNQpr".to_string(),
        allowed_tokens: vec![
            "SOL".to_string(),
            "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr".to_string(),
        ],
        max_amount: "500".to_string(),
    }
}

fn charge(label: &str, amount: &str, token: &str) -> Charge {
    Charge {
        label: label.to_string(),
        amount: amount.to_string(),
        token: token.to_string(),
    }
}

const SALT: &str = "control-salt";

#[test]
fn ceiling_refuses_and_the_control_passes() {
    // planted: one unit over the shop's ceiling
    let over = build_payment_request(&shop(), &charge("table-9", "501", "SOL"), SALT);
    assert!(
        over.is_err(),
        "ceiling did not fire on 501 against a 500 limit — the guard is gone or inverted"
    );

    // control: the same charge at the ceiling must still build, or the test
    // above proves nothing about the ceiling in particular
    let at_limit = build_payment_request(&shop(), &charge("table-9", "500", "SOL"), SALT);
    assert!(
        at_limit.is_ok(),
        "500 was refused against a 500 ceiling: the comparison is off by one, not a control failure"
    );
}

#[test]
fn ceiling_is_decimal_not_lexicographic() {
    // "9" sorts after "500" as a string. If the comparison ever regresses to a
    // string compare this passes when it must refuse, and vice versa.
    let nine = build_payment_request(&shop(), &charge("table-2", "9", "SOL"), SALT);
    assert!(nine.is_ok(), "9 refused against a ceiling of 500 — string comparison regression");

    let big = build_payment_request(&shop(), &charge("table-2", "1000", "SOL"), SALT);
    assert!(big.is_err(), "1000 accepted against a ceiling of 500");
}

#[test]
fn allowlist_refuses_and_the_control_passes() {
    // planted: a mint the shop never listed
    let foreign = build_payment_request(
        &shop(),
        &charge("table-4", "10", "So11111111111111111111111111111111111111112"),
        SALT,
    );
    assert!(
        foreign.is_err(),
        "an unlisted mint was accepted — the allowlist is not being consulted"
    );

    // control: a listed mint must build
    let listed = build_payment_request(
        &shop(),
        &charge("table-4", "10", "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr"),
        SALT,
    );
    assert!(listed.is_ok(), "a listed mint was refused");
}

#[test]
fn empty_allowlist_accepts_nothing() {
    // The dangerous default. An operator who leaves the list empty should get a
    // till that refuses everything, never one that waves everything through.
    let mut cfg = shop();
    cfg.allowed_tokens.clear();

    let any = build_payment_request(&cfg, &charge("table-1", "1", "SOL"), SALT);
    assert!(
        any.is_err(),
        "an empty allowlist accepted a charge — empty must mean deny, not allow-all"
    );
}

#[test]
fn bad_recipient_refuses_and_the_control_passes() {
    let mut cfg = shop();
    cfg.recipient = "not-a-public-key".to_string();

    let planted = build_payment_request(&cfg, &charge("table-3", "5", "SOL"), SALT);
    assert!(
        planted.is_err(),
        "an invalid recipient was accepted — a request that cannot be paid would be handed to a customer"
    );

    let control = build_payment_request(&shop(), &charge("table-3", "5", "SOL"), SALT);
    assert!(control.is_ok(), "the valid recipient was refused");
}

#[test]
fn missing_label_refuses() {
    // Without a label the owner cannot tell two pending orders apart, and the
    // settlement poller has nothing to report against.
    let blank = build_payment_request(&shop(), &charge("   ", "5", "SOL"), SALT);
    assert!(blank.is_err(), "a charge with no order label was accepted");
}

#[test]
fn references_do_not_repeat_across_charges() {
    // The reference is what makes one payment distinguishable from another when
    // several orders share one shop wallet. Two charges sharing a reference
    // would make settlement ambiguous, which is worse than no detection at all.
    let a = build_payment_request(&shop(), &charge("table-1", "10", "SOL"), "salt-a").unwrap();
    let b = build_payment_request(&shop(), &charge("table-1", "10", "SOL"), "salt-b").unwrap();
    assert_ne!(
        a.reference, b.reference,
        "identical charges produced the same reference — settlement cannot tell them apart"
    );
}

#[test]
fn native_sol_omits_the_spl_token_parameter() {
    // Present-but-empty is not the same as absent; some wallets read an empty
    // value as a mint and quote the wrong asset.
    let sol = build_payment_request(&shop(), &charge("table-6", "1", "SOL"), SALT).unwrap();
    assert!(
        !sol.url.contains("spl-token"),
        "a native SOL request carried an spl-token parameter"
    );

    let spl = build_payment_request(
        &shop(),
        &charge("table-6", "1", "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr"),
        SALT,
    )
    .unwrap();
    assert!(
        spl.url.contains("spl-token=Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr"),
        "an SPL request omitted its mint"
    );
}

#[test]
fn the_amount_is_carried_through_unchanged() {
    // A till that quietly re-renders the amount it charges is worse than one
    // that refuses. 25.10 cannot be represented exactly in binary floating
    // point, so a float round-trip shows up here as 25.099999999999998.
    let r = build_payment_request(&shop(), &charge("table-8", "25.10", "SOL"), SALT).unwrap();
    assert_eq!(r.amount, "25.10", "the amount was reformatted in transit");
    assert!(
        r.url.contains("amount=25.10"),
        "the URL carried an amount that differs from the one requested"
    );
}
