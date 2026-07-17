# Task 6 Report: Threat Model, Usage, License, And Repository Verification

## Scope And Base

- Branch: codex/token-risk-check
- Base: db7e487
- Scope: Task 6 documentation, license, integration checks, and this report.
- No root metadata, generated WASM artifact, release URL, demo, push, PR, or bounty submission was added.

## RED Evidence

Before creating the README, the required term check was run from the repository root:

~~~bash
for term in 'Custody tier: T0' 'Threat model' 'Prompt-injection test' 'rpc_url' 'not_checked' '5,000 basis points'; do
  rg -F "$term" plugins/token-risk-check/README.md
done
~~~

Result: exit code 2. Each of the six searches reported that plugins/token-risk-check/README.md did not exist. This is the recorded RED baseline.

## Documentation And License

Added:

- plugins/token-risk-check/README.md
- plugins/token-risk-check/LICENSE

The README documents T0 custody, verdict semantics, exact configuration, public-value input/output, the threat model, prompt-injection transcript, fixed RPC methods and IDs, slot consistency, the 1 MiB streamed response cap, 8 KiB output cap, no-retry behavior, fail-closed Unknown behavior, limitations, and all stable code groups mechanically cross-checked against the source.

The license is the standard MIT text and matches the package metadata's MIT OR Apache-2.0 expression.

## Code Cross-Check

Stable strings were extracted from src/risk.rs and src/lib.rs, then each was checked for a matching README entry. The source groups are:

- 11 assessment/output reason codes: MINT_AUTHORITY_ACTIVE, FREEZE_AUTHORITY_ACTIVE, TOP_ACCOUNT_CONCENTRATED, TRANSFER_FEE, TRANSFER_HOOK, PERMANENT_DELEGATE, DEFAULT_FROZEN, CONFIDENTIAL_TRANSFER, NON_TRANSFERABLE, UNKNOWN_EXTENSION, OUTPUT_TOO_LARGE.
- 20 core/shim error codes, including the shared INVALID_MINT: INVALID_MINT, INVALID_RPC_URL, MALFORMED_RPC_RESPONSE, JSON_RPC_ERROR, NULL_ACCOUNT, ZERO_SUPPLY, INVALID_LARGEST_ACCOUNT, INCONSISTENT_SUPPLY, INCONSISTENT_SLOTS, RESPONSE_ID_MISMATCH, INVALID_AUTHORITY, UNSUPPORTED_TOKEN_PROGRAM, INVALID_EXECUTE_ARGS, REQUEST_SERIALIZATION_ERROR, HTTP_TRANSPORT_ERROR, HTTP_STATUS_ERROR, HTTP_BODY_READ_ERROR, RESPONSE_TOO_LARGE, RESPONSE_BUFFER_ERROR, RESPONSE_NOT_UTF8.
- 4 limitation codes: LP_STATUS_NOT_CHECKED, TOP_ACCOUNTS_ARE_NOT_UNIQUE_HOLDERS, REASONS_TRUNCATED, EVIDENCE_UNAVAILABLE.
- 1 log-only completion code: ASSESSMENT_COMPLETE.

The README contains all source codes above and does not present verdict values as reason codes. red, amber, green, and unknown are documented separately as verdict semantics.

## Integration Decision

No root metadata was changed. README.md states that registry.json is a generated index and that the publish workflow builds and stages each plugins/* manifest. tools/build-registry.py and the workflow therefore provide the established source registration path; hand-editing registry.json would add a premature release URL/hash and would require a committed WASM artifact that Task 6 explicitly excludes. The plugin manifest already declares the supported tool capability and http_client/config_read permissions.

## Verification

The following checks were run after the documentation changes:

~~~bash
for term in 'Custody tier: T0' 'Threat model' 'Prompt-injection test' 'rpc_url' 'not_checked' '5,000 basis points'; do
  rg -F "$term" plugins/token-risk-check/README.md
done

(cd plugins/token-risk-check && cargo test)
(cd plugins/token-risk-check && cargo clippy --all-targets -- -D warnings)
(cd plugins/token-risk-check && cargo clippy --target wasm32-wasip2 --all-targets -- -D warnings)
(cd plugins/token-risk-check && cargo fmt --check)
(cd plugins/token-risk-check && cargo build --target wasm32-wasip2 --release)
python3 tools/build-registry.py --help >/dev/null
git diff --check
rg -n 'println!|eprintln!|dbg!' plugins/token-risk-check && exit 1 || true
~~~

The term check found all six terms. The explicit source-code list check found all 36 documented stable codes: `CODE_CROSSCHECK=PASS stable_codes=36`. Host tests passed with 34 integration tests and zero failures. Host and WASM all-target Clippy checks with warnings denied, format check, release WASM build, registry tool help check, diff check, and stdout scan completed with exit code 0. The release artifact was built at `plugins/token-risk-check/target/wasm32-wasip2/release/token_risk_check.wasm`; it remains an untracked build output and is not included in the Task 6 diff.

## Self-Review And Concerns

- The README does not claim a live demo, upstream acceptance, a release URL, or a safety guarantee.
- The prompt-injection example rejects caller-supplied rpc_url, threshold, and method before network access and distinguishes host-injected __config from the model-call schema.
- The endpoint privacy statement identifies the configured RPC service as the trust boundary without suggesting that HTTPS makes the provider trusted.
- The example uses public-looking values and is explicitly illustrative; no secret, key, signature, transaction, or live result is included.
- The root catalog remains untouched by design. The remaining operational gap is external publication and runtime demonstration, which are Task 7 work and were not started.
