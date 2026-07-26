# Safe Hands — one command to prove everything, no live network.
# `just prove-safety` → unit tests (RPC is mocked; zero live network), the
# 20-fixture attack arena, clippy on both targets, and clean wasm32-wasip2
# release builds of all three components. `--locked` throughout for
# reproducibility, matching upstream CI (tools/ci/validate_components.sh).

default: prove-safety

# The full gate a judge runs.
prove-safety: test conformance verify-receipt log-verify audit clippy wasm verify-capabilities component-test
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
    cargo test --locked --manifest-path conformance/Cargo.toml

# Prove each shipped .wasm imports only the capabilities its manifest declares.
# Reads the compiled artifact an operator installs, not the source: a component
# that cannot import wasi:filesystem cannot persist anything, whatever its code
# claims.
verify-capabilities: stage-local
    python tools/ci/verify_capabilities.py

# Execute the shipped components in a real WebAssembly runtime.
#
# Every other recipe here tests the Rust source; this one loads the staged
# .wasm an operator installs, grants it exactly the imports ZeroClaw grants,
# and asserts the refusals come back across the component boundary.
component-test: stage-local
    cargo run --locked --release --manifest-path component-test/Cargo.toml

# Machine-checked proofs of the authorization invariants (Linux/macOS).
#
# Runs against the heap-free model in policy/resolved.rs, which is why it
# terminates in under a second where the same proofs against evaluate() never
# finished at all. policy/tests.rs holds the model and the engine together.
prove:
    cargo kani --manifest-path libs/safe-hands-core/Cargo.toml

# Coverage-guided fuzzing (Linux/macOS; needs nightly + libFuzzer).
#
# Not part of prove-safety: it runs for as long as you give it, and a gate
# has to terminate. Run it before a release, or overnight.
#   just fuzz decode 300
#   just fuzz policy 300
fuzz target="decode" seconds="120":
    cd libs/safe-hands-core/fuzz && cargo +nightly fuzz run {{target}} -- -max_total_time={{seconds}}

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

# The transparency log: replay conformance/log/arena.jsonl from its genesis.
#
# Every entry is re-derived from the bytes and policy it records, then the whole
# chain is recomputed. Offline — it proves the log is internally honest, which
# is everything except that nothing was quietly cut off the end.
log-verify authority="BJqcN1wqvpakoMtu5xVepNHRTVbQohnDAfARtwe9HNcV":
    cargo run --locked --release --manifest-path conformance/Cargo.toml -- --log-verify --log conformance/log/arena.jsonl --authority {{authority}}

# The half that needs the network: check the log against its published head.
#
# The head of this log was signed and posted to Solana devnet by a key this
# repository does not contain. Truncating the log, reordering it, or rewriting
# any decision in it now contradicts a value nobody involved can retract.
#
#   just log-audit "https://api.devnet.solana.com"
log-audit rpc="https://api.devnet.solana.com" authority="BJqcN1wqvpakoMtu5xVepNHRTVbQohnDAfARtwe9HNcV":
    cargo run --locked --release --manifest-path conformance/Cargo.toml -- --log-audit --log conformance/log/arena.jsonl --authority {{authority}} --rpc "{{rpc}}"

# Rebuild the log from scratch: run the attack arena, emit a receipt per
# fixture, and append each one. Reproduces conformance/log/arena.jsonl except
# for its timestamps, which the chain does not commit to.
log-rebuild out="target/log-rebuild":
    #!/usr/bin/env bash
    set -euo pipefail
    authority=BJqcN1wqvpakoMtu5xVepNHRTVbQohnDAfARtwe9HNcV
    rm -rf "{{out}}"
    mkdir -p "{{out}}/receipts"
    cargo run --locked --release --manifest-path conformance/Cargo.toml -- --receipts "{{out}}/receipts"
    for receipt in "{{out}}"/receipts/*.json; do
        cargo run --locked --release --manifest-path conformance/Cargo.toml -- --log-append "$receipt" --log "{{out}}/arena.jsonl" --authority "$authority" >/dev/null
    done
    cargo run --locked --release --manifest-path conformance/Cargo.toml -- --log-verify --log "{{out}}/arena.jsonl" --authority "$authority"

# Build the unsigned transaction that publishes the current head.
#
# Safe Hands holds no key, so this stops at the unsigned bytes exactly like
# every other transaction the suite produces.
log-anchor rpc="https://api.devnet.solana.com" authority="BJqcN1wqvpakoMtu5xVepNHRTVbQohnDAfARtwe9HNcV":
    cargo run --locked --release --manifest-path conformance/Cargo.toml -- --log-anchor --log conformance/log/arena.jsonl --authority {{authority}} --rpc "{{rpc}}"

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
    cargo clippy --locked --manifest-path conformance/Cargo.toml --all-targets -- -D warnings

# wasm32-wasip2 release components for all four plugins.
wasm:
    cargo build --locked --manifest-path plugins/solana-tx-authorize/Cargo.toml --target wasm32-wasip2 --release --target-dir target
    cargo build --locked --manifest-path plugins/spl-transfer-build/Cargo.toml --target wasm32-wasip2 --release --target-dir target
    cargo build --locked --manifest-path plugins/squads-proposal-build/Cargo.toml --target wasm32-wasip2 --release --target-dir target
    cargo build --locked --manifest-path plugins/payment-verify/Cargo.toml --target wasm32-wasip2 --release --target-dir target

# Materialize locally built components in the same package shape used by installs.
stage-local: wasm
    python tools/stage_local.py
