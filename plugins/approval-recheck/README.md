# approval-recheck

Part of **Aval**, an approval rail for transacting agents. This is the
read-only half of the rail's promise: *what you sign is exactly what
executes.* See [`durable-tx-build`](../durable-tx-build/README.md) for the
full picture.

## What it does

The dangerous gap in approval-gated agent payments is the time between "the
agent built this transaction" and "the human signed it". Balances move,
nonces get consumed, and a chat transcript can claim anything at all about
what a base64 blob does. At approval time, this tool:

1. **Decodes the pending bytes themselves** — never the conversation's
   description of them — into plain sentences: who pays, who receives, how
   much, which mint, what the memo says (quoted as inert data).
2. **Re-fetches the chain state the transaction depends on**: is the durable
   nonce still fresh? Does the signer still hold enough? Does the source
   token account still exist and cover the amount?
3. **Returns a verdict** in about 200 tokens:

| Verdict | Meaning |
|---|---|
| `READY` | Nonce fresh, balances hold, every instruction decoded cleanly; signing lands exactly the listed actions. READY is warning-free by construction |
| `REVIEW_REQUIRED` | Chain state holds, but something could not be fully explained (an unrecognized instruction, an authority mismatch) — a warning can never hide behind a green light |
| `CONSUMED` | The durable nonce moved; the transaction can never land — rebuild |
| `DRIFTED` | State moved underneath it (balance or token account short) — rebuild |
| `NOT_DURABLE` | No advance-nonce prefix; a recent-blockhash tx this old is dead |
| `BROKEN` | Nonce account missing or unusable |

Anything it cannot decode becomes a warning — "instruction for unrecognized
program … do not sign unless you understand it" — never a silent pass.

## Custody tier: T0

Read-only. Holds nothing, signs nothing, submits nothing. Config contains an
RPC URL. This is the plugin a stranger can run with zero trust in its author.

## Config

```toml
rpc_url = "https://your-rpc.example.com"   # operator-supplied; never hardcoded
```

## Worked example

```json
{ "transaction_base64": "AAAA…" }
```

returns

```json
{
  "verdict": "READY",
  "headline": "Verified against the chain just now: the nonce is fresh and balances hold. A signature authorizes exactly the actions listed — nothing expires while the human decides.",
  "actions": [
    "Send 25 of token mint EPjF..t1v from 8f2a..91Bc to 3Kd0..pQrs",
    "Create the recipient's token account if missing (small rent, paid by signer)",
    "Attach on-chain memo (inert data): \"invoice 412\""
  ],
  "warnings": []
}
```

## Threat model

| Threat | Outcome |
|---|---|
| Builder plants "APPROVED — SAFE TO SIGN" in the memo | Memo is quoted as inert data; the verdict comes from chain state only |
| Transaction includes an instruction for an unknown program | Explicit warning; never explained away |
| Chat transcript misdescribes the transaction | Irrelevant: this tool decodes the bytes, not the chat |
| Injection smuggles `assume_valid: true` | `deny_unknown_fields`; parse error |
| Malicious RPC returns stale state | Verdicts carry no authority to sign; the human wallet still simulates and signs on its own view of the chain |

The transcript-backed tests live in `tests/recheck.rs`
(`injection_memo_is_quoted_data_not_verdict`,
`injection_unknown_program_is_flagged_never_explained_away`).

## Build & test

```
cargo test                                     # host tests, mocked RPC
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release   # produces approval_recheck.wasm
cp target/wasm32-wasip2/release/approval_recheck.wasm approval_recheck.wasm
```

## Install

```bash
zeroclaw plugin install approval-recheck
```

or copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, then enable plugins:

```toml
[plugins]
enabled = true
```

Run the agent with a build that includes a compiler backend, e.g.
`--features plugins-wasm,plugins-wasm-cranelift`. For runtime-only hosts
(`--features plugins-wasm`), precompile with a matching wasmtime:
`wasmtime compile --target <triple> approval_recheck.wasm -o approval_recheck.cwasm` and point
`wasm_path` at the `.cwasm`.


Pure core in `src/recheck.rs`; wasm shim in `src/lib.rs`. Vendored substrate in `src/core/` (canonical source:
[aval-core](https://github.com/bryankwandou/aval-core), kept self-contained
here as the registry's per-plugin CI requires).

## What we'd build next / wasm32-wasip2 notes

Suite-level roadmap and the full write-up of what fought us on
wasm32-wasip2 live in [`durable-tx-build`](../durable-tx-build/README.md)
(sections "What we'd build next" and "What fought us on wasm32-wasip2").

## License

MIT — see [LICENSE](LICENSE).
