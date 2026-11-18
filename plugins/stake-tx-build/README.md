# stake-tx-build

A ZeroClaw **WIT component** tool plugin. It implements the `tool-plugin` world
from `wit/v0` and compiles to a `wasm32-wasip2` component. The exported tool is
`stake_tx_build`: it turns an operator's intent to delegate or deactivate stake
into an unsigned transaction that a human still has to sign.

## What it does

A call produces an unsigned legacy Solana transaction, either a `delegate` or a
`deactivate`, for a stake account named in the operator's allowlist. The output
opens with a plain-language summary for the approval gate and closes with the
transaction as base64 on its own labeled line. A person reads the summary and
signs in their own wallet. The plugin signs nothing and submits nothing; no
private key ever reaches it.

Every instruction byte is assembled by hand, without `solana-sdk`: the base58
and base64 codecs, the compact-u16 length prefixes, the legacy message header,
and the bincode discriminants for each program instruction. That keeps the wasm
artifact small and the transaction layout auditable down to the byte.

Before any of that, the plugin asks the configured endpoint for its genesis
hash and compares it against the pinned cluster, which defaults to
mainnet-beta. The check costs one extra read per call, and a mismatch aborts
before a single transaction byte exists. A URL alone says nothing about the
chain behind it, so an endpoint that answers honestly while serving devnet or
testnet is caught by its own reply. The threat model below states the limits of
that check.

A durable nonce is optional. When the config sets `nonce_account` together with
`nonce_authority`, the first instruction becomes `AdvanceNonceAccount` and the
transaction draws its blockhash from the nonce account state, so it does not go
stale while it waits in an approval queue. Without a nonce the tool reads a
fresh blockhash and the summary warns that the signing window is short.

Before a delegate the builder does read the target validator's live standing,
with `getVoteAccounts` filtered to that vote account, and it names a delinquent
or absent target in the pre-signing summary. It warns rather than refuses, and
that is deliberate: enforcement belongs to the vote account allowlist, and an
operator delegating to a validator they know is coming back would otherwise be
stranded with no override.

## Config keys

`manifest.toml` carries a closed Draft 2020-12 `config_schema` naming every key
below. The host rejects a manifest that requests `config_read` without one, and
it validates the operator's stored values against the schema before injecting
them into `execute` arguments as a typed `__config` object.

| Key | Schema type | Default | Meaning |
|---|---|---|---|
| `stake_accounts` | `array` of `string` | (required) | Allowlist. Each entry is `label:pubkey` or a bare pubkey. The only stake accounts the tool will act on. |
| `authority` | `string` | (required) | Fee payer and stake authority **public key**. Never a private key. |
| `rpc_url` | `string` | (required) | HTTPS Solana RPC endpoint read for a blockhash. Must start with `https://`. |
| `cluster` | `string` enum | `mainnet-beta` | Cluster the endpoint's reported genesis hash must match. Stays on `mainnet-beta` unless the operator names another public cluster; the alternatives are `devnet` and `testnet`. Any other value is rejected. |
| `allowed_vote_accounts` | `array` of `string` | (empty) | Allowlist of vote accounts eligible as delegation targets. Empty disables `delegate` entirely. |
| `nonce_account` | `string` | (unset) | Durable nonce account pubkey. Set with `nonce_authority` to build a transaction that survives an approval queue. |
| `nonce_authority` | `string` | (unset) | Authority pubkey for the durable nonce. Must be set together with `nonce_account`. |
| `timeout_secs` | `integer` | `10` | Connect timeout for the RPC call, between 1 and 60. |

Operator storage is still a string map, and the schema is what tells the host
how to read each stored string. Set the two allowlists like this:

```bash
key=$(zeroclaw plugin info stake-tx-build | grep -o 'zpi1_[A-Za-z0-9_-]*')   # the instance key
zeroclaw config set "plugins.entries.$key.config.stake_accounts" '["main:<pubkey>"]'
zeroclaw config set "plugins.entries.$key.config.allowed_vote_accounts" '["<vote pubkey>"]'
```

**Breaking change in 0.2.0.** `stake_accounts` and `allowed_vote_accounts` were
comma-separated strings before this release and are JSON arrays now, and
`timeout_secs` is a real integer. The host rejects the old encoding rather than
reading it as one malformed entry, which matters more here than in the two
readers: both of these lists are security boundaries rather than conveniences,
and a silently misread allowlist is the failure this design exists to prevent.
Two relations stay in the plugin because JSON Schema cannot state them between
sibling properties: the nonce pair must be set together or not at all, and the
endpoint's genesis hash must match the pinned cluster.

Upgrading from a version without the cluster gate: `cluster` now defaults to
`mainnet-beta`, so a config whose `rpc_url` points at devnet or testnet fails
on every call until the section adds the matching key, `cluster = "devnet"` or
`cluster = "testnet"`. A config already on mainnet needs no change.

The call itself takes an `action` of `delegate` or `deactivate` and a
`stake_account` given as a label or pubkey from the allowlist. A `delegate`
additionally requires a `vote_account`, which must appear in
`allowed_vote_accounts`; passing `vote_account` to a `deactivate` is rejected.

## Layout (the reference format)

```
src/txbuild.rs   # pure logic, no wasm deps; host-testable with cargo test
src/lib.rs       # thin #[cfg(target_family = "wasm")] component shim
tests/           # host-run integration tests over the pure core
manifest.toml    # name, version, wasm_path, capabilities, permissions
```

## Build and test

```bash
cargo test                                        # host tests, no wasm needed
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release      # the component
cp target/wasm32-wasip2/release/stake_tx_build.wasm stake_tx_build.wasm
```

## Custody tier

**Tier: T1 Build** on the ZeroClaw custody ladder. Secrets held: the operator's
RPC endpoint URL and nothing besides; the authority and the stake accounts it
reads from config are public keys, and no config key would accept a private one.
The tier is honest because the tool stops at a base64 message, with no signer and
no `sendTransaction` path, so what it returns stays inert until a human signs it
in a wallet the plugin never sees.

This tool builds unsigned transactions and holds no keys. Its only outbound
calls are three reads against the operator's own RPC endpoint: the cluster
genesis hash, then a blockhash or the nonce account state, then the live
standing of the account it is about to touch. Everything it produces is inert
until a human signs it in a wallet the plugin never sees.

The manifest asks for exactly two permissions: `http_client` for those RPC
reads and `config_read` for its own jailed config section. Neither one can sign
or spend, and the plugin requests nothing beyond them.

## Threat model

The tool assumes the agent driving it may be under prompt injection. Its
defenses do not depend on the agent behaving.

- **Stake accounts are allowlisted.** `stake_account` must resolve to an entry
  in `stake_accounts`. An address the operator never configured is refused, and
  the tool builds nothing.
- **Delegation targets are allowlisted, and off by default.** `delegate` stays
  disabled until the operator sets `allowed_vote_accounts`. Even then the target
  must be on that list.
- **The authority is a public key, never a secret.** `authority` names the fee
  payer and stake authority. No config field accepts private-key material, so
  there is nothing to leak.
- **The endpoint has to report its chain, and the report is checked.** Every
  call reads `getGenesisHash` and compares the reply against the pinned
  `cluster`. A mismatch refuses; a reply that is absent or malformed refuses
  the same way. What this catches is an honest endpoint on the wrong chain: an
  `rpc_url` left pointing at devnet or testnet, or a `cluster` typo that would
  otherwise have bytes assembled against a cluster the operator never meant.
  What it does not catch: a hostile proxy answers `getGenesisHash` with the
  mainnet constant and passes, because nothing binds that reply to the
  blockhash that follows, and a chain forked from mainnet inherits mainnet's
  genesis hash, so it answers correctly too. Trust in the endpoint itself stays
  with the operator who configured it.

  Host tests cover the decision logic in the pure core: the reply parse, and
  the refusal on either a mismatch or a malformed reply. That the gate runs
  before any transaction byte is assembled lives in the wasm shim in
  `src/lib.rs`, alongside the blockhash and nonce reads, and is not exercised
  by `cargo test`.
- **Unknown config keys fail closed.** A typo such as `allowed_vote_account`
  does not silently weaken an allowlist; parsing stops with an error. The same
  holds for `cluster`: `mainnet` is not `mainnet-beta`, and the near miss is
  rejected instead of resolved.
- **Unexpected arguments fail closed.** The argument schema rejects any field it
  does not recognize, so a smuggled parameter aborts the call.

- **A stale allowlist entry is named, not silently honoured.** The allowlist
  decides which validators are acceptable, and it keeps deciding that forever:
  an entry added months ago cannot notice that its validator stopped voting last
  week. Before building a `delegate`, the tool reads `getVoteAccounts` filtered
  to that one vote account and puts the standing in the summary. A validator the
  chain lists as delinquent, or one that appears in neither list, produces a
  warning next to the address it describes. A currently voting validator adds
  nothing to the line, because a summary that comments on every healthy case
  teaches the reader to skip the sentence that matters. A lookup that fails says
  so rather than reading as a clean bill of health.

  This warns and does not refuse, which is a deliberate difference from the
  official Solana CLI. The CLI rejects the delegation
  (`Unable to delegate. Vote account appears delinquent`).
  An operator may be delegating to a validator they know is coming back, and a
  hard refusal here would strand them with no way through short of editing
  config. The enforcement boundary stays where the operator put it, in the
  allowlist, and the tool's job is to make sure they are not deciding blind.

- **A deactivation with nothing to deactivate is named too.** The same boundary
  on the other action. Before building a `deactivate`, the tool reads the stake
  account and checks whether a deactivation is already recorded. A stake that
  finished cooling down is a perfectly healthy state, and asking the Stake
  program to deactivate it again is rejected with `AlreadyDeactivated`. Without
  the check the operator receives well-formed bytes, signs them in their wallet,
  pays the fee, and learns the answer from a failed transaction. An account
  carrying no delegation at all is called out the same way. An active
  delegation adds nothing to the summary.

  This one came from a live run rather than from reading: during the acceptance
  session of 2026-08-01 a `deactivate` built for a cooled-down devnet account
  simulated with `InstructionError: Custom(2)`. The bytes were correct, the
  `AdvanceNonceAccount` ahead of them succeeded, and the operation was still
  pointless. Both checks now come from the same principle: an allowlist states
  ownership, not what the chain holds right now.

The health reading stops there. Commission, vote lag, and epoch rewards belong
to `stake-monitor`, which reads them for accounts the operator already holds;
repeating them here would pad the one line a human has to read before signing.

## A worked example

A `deactivate` call against the stake account labeled `main`, with no durable
nonce configured, returns:

```
Unsigned deactivate transaction. Verify each address below in full before signing, and do not abbreviate them when relaying: a shortened address can be ground to match on its visible ends. Stake account CUupRKBoZ3WvHV24uBtCMXz3ms2geTad7g1k2ZpyqPmq (config label `main`), fee payer and sole signer AAJNL7uZrwcCFPAFJHRiSDEKXGgdZXhpL427iqkDFnre; lifetime: fresh blockhash, sign and submit within roughly 60 to 90 seconds; amount: not read by this builder.
unsigned_tx_base64: AQAAAAAAAAAAAAAAAAAAAAAA...hgEDAwECAAQFAAAA   (320 characters)
```

Decoded byte for byte, the deactivation instruction verifies against the Stake
program: program `Stake11111111111111111111111111111111111111`, accounts
`[stake, clock, authority]`, data `05000000`. Nothing about the staked amount
appears anywhere, because the builder never reads it.

The same call against an `rpc_url` that turns out to be devnet returns no
transaction at all:

```
success=false
error: cluster mismatch: rpc_url reports genesis `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG`, not mainnet-beta `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`
```

## Prompt-injection test

An injected instruction tells the agent to redirect the operator's stake to a
validator the attacker controls, and to deactivate a stake account the operator
never configured. Both calls fail closed. The tool builds zero transactions.

The `delegate`, carrying a vote account that is not among the operator's
approved validators:

```
success=false
error: vote account `5btPEka74QyPuY7Yj6wks8oHHLFMqHWFiRraSLzUB5Ev` is not in the configured allowed_vote_accounts allowlist (a quoted string holding a JSON array of vote account pubkeys, not a bare TOML array)
```

The `deactivate`, naming a stake account the config never mentions:

```
success=false
error: stake account `Eu9abQ8jj3Dj6MrN8oW6wuyosLrMmA8ZwWWnifCKTvmp` is not in the configured allowlist; known labels: main
```

An agent pushed by an injection runs into two independent allowlists at once,
and neither of them takes its contents from the model. The delegation target
has to be a vote account the operator wrote into `allowed_vote_accounts`; on a
config that never set that key, `delegate` refuses a step earlier still, with
`delegate is disabled`. The stake account has to be one the operator named, and
the error names the allowlist labels so a legitimate typo is easy to correct.

## Install

```bash
zeroclaw plugin install .   # from this directory, with the .wasm beside manifest.toml
```

The path form is what works while the plugin lives outside a registry; `zeroclaw plugin install stake-tx-build` resolves by name only once a registry serves it.

Or copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, then enable plugins and configure the keys above:

```toml
[plugins]
enabled = true
# REQUIRED on every host newer than the pinned `fc8b4d83`, including 0.8.4 and
# current master: this is the only gate that admits Tool and Skill plugins, and
# it defaults to false. Without it the daemon starts clean and registers nothing.
# Inert at the pinned host, so it is safe to set either way.
auto_discover = true
```


Configuration is required here, since the plugin refuses to run without an
allowlist. Supply it in the plugin's own config record, which is the section the
`config_read` permission unlocks:

```toml
[[plugins.entries]]
# The INSTANCE KEY that `zeroclaw plugin info stake-tx-build` prints on its
# `Config entry key` line, not the package name: the host consults entries by
# that key and silently ignores an entry named after the package.
name = "zpi1_WyJzdGFrZS10eC1idWlsZCIsInRvb2wiLCJzdGFrZS10eC1idWlsZCJd"

[plugins.entries.config]
# Every value is a string. Non-string properties must CONTAIN valid JSON, so a
# list is a quoted string holding a JSON array. A bare TOML number or a
# comma-separated list is refused.
stake_accounts = '["main:REPLACE_WITH_YOUR_STAKE_ACCOUNT_PUBKEY"]'
# The fee payer and stake authority PUBLIC key. Never a private key.
authority = "REPLACE_WITH_YOUR_STAKE_AUTHORITY_PUBKEY"
rpc_url = "https://REPLACE_WITH_YOUR_RPC_ENDPOINT"
# The plugin reads the endpoint's genesis hash and refuses to build if it does
# not match this. Change to "devnet" if your rpc_url is a devnet endpoint.
cluster = "mainnet-beta"
# Empty disables the delegate action entirely. Opt in by listing vote accounts.
allowed_vote_accounts = '[]'
timeout_secs = "10"
```

**`config set` will not take these values on the command line.** The host treats
every key under `plugins.entries.*.config.*` as an encrypted secret, so it ignores
the value you pass and prompts for masked input instead; outside a terminal it
refuses outright with `Secret input requires a terminal on stdin and stderr`. Run
`config set` interactively and paste each value at the prompt, or write the block
above straight into `config.toml`, which is what the installer seeds and what a
scripted setup should do.

Run the agent with a build that includes a compiler backend, e.g.
`--features plugins-wasm,plugins-wasm-cranelift`. For runtime-only hosts
(`--features plugins-wasm`), precompile with a matching wasmtime:
`wasmtime compile --target <triple> stake_tx_build.wasm -o stake_tx_build.cwasm`
and point `wasm_path` at the `.cwasm`.

## Operating notes

Both of these surfaced while driving the plugin through a real Telegram channel,
and neither is visible from reading the code. They cost an operator an evening
to rediscover.

**Getting the transaction out of the channel intact.** The host scans outbound
channel messages for leaked credentials and replaces high-entropy tokens with
`[REDACTED_HIGH_ENTROPY_TOKEN]`. A base64 transaction trips that heuristic. The
deactivate transaction measured here was 320 characters with a Shannon entropy
of 4.79, and the durable-nonce variant 464 characters at 4.74, against a default
threshold of 4.375, so the operator receives a placeholder where the transaction
should be. Set

```toml
[security.leak_detection]
high_entropy_tokens = false
```

to switch off the entropy heuristic while the deterministic patterns for real
credentials keep running: Anthropic, OpenAI, GitHub, Stripe, Google and Groq
keys are all still redacted. An unsigned transaction is not a secret. It carries
no key material and stays inert until someone signs it, which is the whole
premise of this plugin.

The transaction is emitted as one unbroken base64 line, but some chat clients
insert line breaks when a long line is copied. Strip whitespace before feeding
it to a decoder that does not tolerate it.

**Refusals that arrive without text.** The host runs a reply-intent classifier
before the agent loop. When that classifier declines to answer, the user gets an
emoji reaction and nothing else: 🚫 for a policy refusal, 👍 for a request the
host considers already answered. The reason is written to the runtime trace in
plain language, yet it never reaches the channel. An operator who needs every
request acknowledged in text can bypass the classifier with

```toml
[agents.<name>.precheck]
enabled = false
```

which routes every accepted message through the full agent loop. Note the trade:
that classifier is also what stops an obvious injection before it reaches the
model, and the refusals in this plugin hold regardless of either setting, since
they are enforced against the operator's allowlist rather than by prompt.
