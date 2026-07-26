# Safe Hands — one command to prove everything, no live network.
# `just prove-safety` → unit tests (RPC is mocked; zero live network), the
# 20-fixture attack arena, clippy on both targets, and clean wasm32-wasip2
# release builds of all three components. `--locked` throughout for
# reproducibility, matching upstream CI (tools/ci/validate_components.sh).

default: prove-safety

# The full gate a judge runs.
prove-safety: test conformance verify-receipt audit clippy wasm
    @echo ""
    @echo "=================================================="
    @echo "  prove-safety: ALL GREEN — the guard holds."
    @echo "=================================================="

# Host tests for every crate (mocked RPC, zero network).
test:
    cargo test --locked --manifest-path libs/safe-hands-core/Cargo.toml
    cargo test --locked --manifest-path plugins/solana-tx-authorize/Cargo.toml
    cargo test --locked --manifest-path plugins/spl-transfer-build/Cargo.toml
    cargo test --locked --manifest-path plugins/squads-proposal-build/Cargo.toml
    cargo test --locked --manifest-path plugins/payment-verify/Cargo.toml

# Supply-chain gate over every pinned lockfile.
#
# RUSTSEC-2025-0141 (bincode unmaintained) is accepted knowingly and cannot be
# fixed by upgrading: Solana's wire format IS bincode-1 (fixint,
# little-endian), and bincode 2/3 changed it. Moving off 1.3.3 would silently
# change the bytes this project exists to encode exactly. Everything else —
# any new advisory, vulnerability or warning — fails the gate.
audit:
    #!/usr/bin/env bash
    set -euo pipefail
    for crate in libs/safe-hands-core plugins/payment-verify plugins/solana-tx-authorize                  plugins/spl-transfer-build plugins/squads-proposal-build conformance; do
        echo "audit: $crate"
        (cd "$crate" && cargo audit --deny warnings --ignore RUSTSEC-2025-0141)
    done

# The attack arena — every fixture in conformance/fixtures/.
conformance:
    cargo run --locked --release --manifest-path conformance/Cargo.toml

# Re-derive a recorded decision from its inputs. Proves the verdict was
# computed, not asserted — and that a forged receipt cannot pass.
verify-receipt receipt="conformance/receipts/live-allow.json":
    cargo run --locked --release --manifest-path conformance/Cargo.toml -- --verify {{receipt}}

# clippy -D warnings on host and wasm targets, matching upstream CI.
clippy:
    cargo clippy --locked --manifest-path libs/safe-hands-core/Cargo.toml --all-targets -- -D warnings
    cargo clippy --locked --manifest-path plugins/solana-tx-authorize/Cargo.toml --all-targets -- -D warnings
    cargo clippy --locked --manifest-path plugins/spl-transfer-build/Cargo.toml --all-targets -- -D warnings
    cargo clippy --locked --manifest-path plugins/squads-proposal-build/Cargo.toml --all-targets -- -D warnings
    cargo clippy --locked --manifest-path plugins/payment-verify/Cargo.toml --all-targets -- -D warnings
    cargo clippy --locked --manifest-path libs/safe-hands-core/Cargo.toml --target wasm32-wasip2 -- -D warnings
    cargo clippy --locked --manifest-path plugins/solana-tx-authorize/Cargo.toml --target wasm32-wasip2 -- -D warnings
    cargo clippy --locked --manifest-path plugins/spl-transfer-build/Cargo.toml --target wasm32-wasip2 -- -D warnings
    cargo clippy --locked --manifest-path plugins/squads-proposal-build/Cargo.toml --target wasm32-wasip2 -- -D warnings
    cargo clippy --locked --manifest-path plugins/payment-verify/Cargo.toml --target wasm32-wasip2 -- -D warnings

# wasm32-wasip2 release components for all four plugins.
wasm:
    cargo build --locked --manifest-path plugins/solana-tx-authorize/Cargo.toml --target wasm32-wasip2 --release --target-dir target
    cargo build --locked --manifest-path plugins/spl-transfer-build/Cargo.toml --target wasm32-wasip2 --release --target-dir target
    cargo build --locked --manifest-path plugins/squads-proposal-build/Cargo.toml --target wasm32-wasip2 --release --target-dir target
    cargo build --locked --manifest-path plugins/payment-verify/Cargo.toml --target wasm32-wasip2 --release --target-dir target

# Materialize locally built components in the same package shape used by installs.
stage-local: wasm
    python tools/stage_local.py
