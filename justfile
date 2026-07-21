# Safe Hands — one command to prove everything, offline.
# `just prove-safety` → unit tests, the 20-fixture attack arena, clippy on both
# targets, and clean wasm32-wasip2 release builds of all three components.

default: prove-safety

# The full gate a judge runs.
prove-safety: test conformance clippy wasm
    @echo ""
    @echo "=================================================="
    @echo "  prove-safety: ALL GREEN — the guard holds."
    @echo "=================================================="

# Host tests for every crate (mocked RPC, zero network).
test:
    cargo test --manifest-path libs/safe-hands-core/Cargo.toml
    cargo test --manifest-path plugins/solana-tx-authorize/Cargo.toml
    cargo test --manifest-path plugins/spl-transfer-build/Cargo.toml
    cargo test --manifest-path plugins/squads-proposal-build/Cargo.toml

# The 20-fixture attack arena.
conformance:
    cargo run --release --manifest-path conformance/Cargo.toml

# clippy -D warnings on host and wasm targets, matching upstream CI.
clippy:
    cargo clippy --manifest-path libs/safe-hands-core/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path plugins/solana-tx-authorize/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path plugins/spl-transfer-build/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path plugins/squads-proposal-build/Cargo.toml --all-targets -- -D warnings
    cargo clippy --manifest-path libs/safe-hands-core/Cargo.toml --target wasm32-wasip2 -- -D warnings
    cargo clippy --manifest-path plugins/solana-tx-authorize/Cargo.toml --target wasm32-wasip2 -- -D warnings
    cargo clippy --manifest-path plugins/spl-transfer-build/Cargo.toml --target wasm32-wasip2 -- -D warnings
    cargo clippy --manifest-path plugins/squads-proposal-build/Cargo.toml --target wasm32-wasip2 -- -D warnings

# wasm32-wasip2 release components for all three plugins.
wasm:
    cargo build --locked --manifest-path plugins/solana-tx-authorize/Cargo.toml --target wasm32-wasip2 --release
    cargo build --locked --manifest-path plugins/spl-transfer-build/Cargo.toml --target wasm32-wasip2 --release
    cargo build --locked --manifest-path plugins/squads-proposal-build/Cargo.toml --target wasm32-wasip2 --release
