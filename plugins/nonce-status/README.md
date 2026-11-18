# nonce-status

Inspect a **durable nonce account**: current nonce value, authority, rent
state, and whether `spl-transfer-build` can use it right now. Read-only, one
RPC call.

Durable nonces are what keep an approval-gated agent payment alive: a
transaction built on a fresh blockhash dies in about a minute, one built on a
durable nonce stays valid until it lands. That makes the nonce account a
small piece of operational state worth watching — and when a transfer build
fails, "what state is my nonce account in?" is the first question. This tool
answers it in the chat:

```
READY: nonce account 8Xko… — authority 9B5X…, current nonce 4fGh8p2Qk…,
fee 5000 lamports/sig. transfer-build transactions built against it stay
valid until the nonce advances (i.e. until one of them lands).
```

Non-happy paths are diagnosed, not guessed: `MISSING` (with the exact
`solana create-nonce-account` commands to fix it), `NOT A NONCE ACCOUNT`
(wrong owner), `UNINITIALIZED`, and `UNUSABLE` for legacy-version nonces
that the current runtime never validates.

## What this component does and does not do

- One `getAccountInfo` call, parsed against the 80-byte nonce layout.
- Holds no keys, moves nothing, signs nothing, creates nothing: account
  creation is a deliberate operator action, done once with the Solana CLI.

## Config

The host must be built with the WASM plugin backend
(`--features plugins-wasm-cranelift`, which implies `plugins-wasm`).

```toml
[plugins]
enabled = true

[[plugins.entries]]
name = "nonce-status"

[plugins.entries.config]
rpc_url = "https://api.devnet.solana.com"
# Default account to inspect; spl-transfer-build's nonce_account. An explicit
# `account` argument (read-only) overrides it.
nonce_account = ""
```

Once the typed-config host lands (issue #147), `[[plugins.entries]]` is keyed on
the package's full instance id rather than its name, and legacy name-keyed entries
are not consulted. Set the same values through the CLI, which resolves the key for
you:

```
key=$(zeroclaw plugin info nonce-status)   # prints the zpi1_... instance key
zeroclaw config set "plugins.entries.$key.config.rpc_url" 'https://api.devnet.solana.com'
zeroclaw config set "plugins.entries.$key.config.nonce_account" ''
```

The manifest declares a closed `config_schema`, so the host validates these values
and rejects an unknown key before the component starts. The guest checks them
again rather than trusting the host's copy.

Unknown config keys are rejected, `rpc_url` must be https and cannot be
supplied as a call argument (fail closed on all three).

## Threat model

Read-only and stateless, so the surface is minimal: the tool cannot be
prompt-injected into moving anything because it has no write path at all. The
remaining defenses mirror its siblings: `deny_unknown_fields` on arguments
(an injected `rpc_url` fails parsing —
`tests/core.rs::injected_unknown_arg_rejected`), operator-only endpoint,
strict account-data parsing that fails closed on every malformed branch
(wrong length, unknown version/state tags, wrong owner).

## What fought us on wasm32-wasip2

The nonce account state is bincode-encoded by the runtime, but it is a fixed
80-byte layout (u32 versions tag, u32 state tag, 32-byte authority, 32-byte
nonce, u64 fee) — hand-parsed in `solana-core-wasi::nonce` and verified
against devnet post-state during development. Legacy-version nonces (tag 0)
are rejected explicitly: the current runtime never validates them, so
reporting one as READY would be a lie.

## What we'd build next

A `nonce-create-build` companion (unsigned) so the whole lifecycle can be
proposed from the chat and signed by the owner, closing the one remaining CLI
step.

## License

MIT.
