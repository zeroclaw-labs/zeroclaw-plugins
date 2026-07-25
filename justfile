# Safe Hands — one command to prove everything, no live network.
# `just prove-safety` → unit tests (RPC is mocked; zero live network), the
# 20-fixture attack arena, clippy on both targets, and clean wasm32-wasip2
# release builds of all three components. `--locked` throughout for
# reproducibility, matching upstream CI (tools/ci/validate_components.sh).

default: prove-safety

# The full gate a judge runs.
prove-safety: test conformance clippy wasm
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

# The attack arena — every fixture in conformance/fixtures/.
conformance:
    cargo run --locked --release --manifest-path conformance/Cargo.toml

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
