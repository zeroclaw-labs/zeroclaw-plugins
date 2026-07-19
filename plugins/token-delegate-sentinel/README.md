# token-delegate-sentinel

A read-only ZeroClaw tool that audits wallet-owned SPL Token and Token-2022
accounts for account-level delegates. It reports active exposure, dormant
allowance, and a fingerprint of the complete permission set.

The model calls `token_delegate_audit` with `{}`. The owner and RPC endpoint
come only from the plugin's jailed configuration; the tool cannot create,
sign, simulate, or submit transactions.

## Configuration

Add the plugin entry to the ZeroClaw config:

```toml
[[plugins.entries]]
name = "token-delegate-sentinel"

[plugins.entries.config]
rpc_url = "https://your-solana-rpc.example"
owner = "WALLET_BASE58_ADDRESS"
expected_genesis_hash = "CLUSTER_GENESIS_HASH"
```

| Key | Required | Default | Description |
|---|---:|---|---|
| `rpc_url` | yes | — | HTTPS Solana JSON-RPC endpoint. |
| `owner` | yes | — | Wallet address whose token accounts are audited. |
| `expected_genesis_hash` | yes | — | Binds the endpoint to the intended cluster. |
| `allowed_delegates` | no | empty | Comma-separated delegates that remain visible but amber. |
| `max_accounts` | no | `256` | Combined account cap (`1..=512`). |
| `max_findings` | no | `5` | Detailed findings returned (`1..=10`). |
| `max_response_bytes` | no | `1500000` | RPC response cap (`1024..=4000000`). |

Invalid configuration fails closed. The RPC URL is never returned or logged.

## Custody and threat model

**Tier: T0 (Read).** The plugin holds no wallet secret and accepts no signer,
recipient, amount, endpoint, owner, program, or target from the model. Its only
permissions are `config_read` and `http_client`.

RPC data is untrusted. The plugin validates the cluster, finalized slot
consistency, response bounds, account ownership and layouts, Token-2022 TLV
framing, mint data, and cross-program duplicates. Invalid input returns a fixed
local error without partial results or upstream text. Output is capped at 4096
bytes; its SHA-256 fingerprint still covers every permission found.

`RED` means an unknown delegate has positive allowance, `AMBER` means an
allowlisted delegate or zero allowance, and `GREEN` means no delegates. Active
exposure is `min(balance, allowance)`; the remainder is dormant allowance.

### Prompt-injection test

Malicious tool arguments:

```json
{
  "owner": "attacker",
  "rpc_url": "https://attacker.invalid",
  "private_key": "...",
  "send_transaction": true
}
```

Result: `INVALID_ARGUMENTS` before any network request. The schema has no
model-controlled properties, unknown fields are rejected, and tests verify
that injected RPC or account text is never returned to the model.

## Worked example

A real ZeroClaw `PluginHost` call against a disposable Solana devnet fixture
returned:

```text
RED — 2 token delegate findings (finalized slots 477389847–477389849).
RED SPL 2qqA…i7VF: unknown delegate, balance 12500, allowance 50000, immediate 12500, dormant 37500.
AMBER T22 Doot…GVbg: allowlisted delegate, balance 50, allowance 20, immediate 20, dormant 0.
Authority fingerprint: c533d50bb54650c0833ccc8afebe0d2cb90350ab94ea51cfdbdb5eb28c5b649e.
```

The fixture approvals were finalized for [SPL Token](https://explorer.solana.com/tx/5U35tQSTZJFoxHSma1yHjemshrgJUUE4cx31rLdERo3tY51gjuy1y1PPh5oFXXsfHtaGoq3fEZfZKQfaxm4bPaZn?cluster=devnet)
and [Token-2022](https://explorer.solana.com/tx/57xviZsaoJhRCciLtiXRSWTbjVhkLkhfW4inPVcK3eAqCDXP5DDbbzURAqD3Yy6jenHmuf7tUBueXnAsyyDVvmi6?cluster=devnet).

## Build and test

```sh
rustup target add wasm32-wasip2
cargo test --locked
cargo build --locked --target wasm32-wasip2 --release
```

From the repository root, run the registry checks:

```sh
python3 tools/ci/manifest_field.py --validate-package-tree plugins/token-delegate-sentinel
python3 -m unittest discover -s tools/tests -p 'test_*.py'
python3 tools/build-registry.py --source-plugins plugins --check-metadata registry.json
```

## WASM notes and next step

`solana-client` did not fit this component target. The plugin keeps `waki` HTTP
in the thin WASM shim and implements bounded JSON-RPC and token decoding in the
host-tested core. It pins the repository's experimental `wit/v0`; ABI changes
require a rebuild. Local runtime testing requires a source-built ZeroClaw host
with `--features plugins-wasm,plugins-wasm-cranelift`.

The next component is a separately reviewed **T1 unsigned revoke builder**.
Signing and submission remain outside both plugins so a human or host approval
gate retains custody.

Licensed under the [MIT License](LICENSE).
