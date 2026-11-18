# stake-monitor

A ZeroClaw **WIT component** tool plugin. It implements the `tool-plugin` world
from `wit/v0` and compiles to a `wasm32-wasip2` component. It exposes one tool,
`stake_monitor`, that reads the on-chain status of the operator's own stake
accounts over Solana JSON-RPC and shapes the result for a chat agent. Read-only:
the plugin holds no keys and signs nothing.

## What it does

Point the tool at an allowlist of stake accounts the operator already controls
and at a Solana RPC endpoint. It returns a short briefing, one line per account,
sized to fit an agent turn without flooding the context.

Each account line carries the delegation lifecycle status, how much SOL is
delegated, the validator's health, and whether the account earned a reward in
the previous epoch. The lifecycle status is one of `activating`, `active`,
`deactivating`, or `inactive`; an account with no delegation is reported as such.
A header line counts the accounts, sums the delegated stake, names the current
epoch with its progress and a rough "hours left" hint, and raises a `DELINQUENT`
or `BEHIND` flag when a validator earns one.

The reading is assembled from a few narrow RPC calls. `getEpochInfo` gives the
epoch and the network head slot, plus the progress and time-left figures.
`getAccountInfo` with `jsonParsed` yields the delegation. `getVoteAccounts` is
filtered by `votePubkey` so the reply is a single validator record instead of
the whole roster. `getInflationReward` for the prior epoch supplies the last
reward. The optional `account` argument selects one allowlisted entry by label
or pubkey; omit it to report every configured account.

## Drift before delinquency

Delinquency is a verdict, and by the time the RPC hands it down the stake has
already missed rewards. The earlier signal is vote lag: how far the validator's
last vote trails the network head, in slots. A healthy node sits within a slot
or two of the head. Past `vote_lag_warn_slots` the line is marked `BEHIND` and
the header counts it, which gives the operator a window to act while the
validator is still voting. The default threshold is 32 slots, roughly 13 seconds
of missed voting.

That default is a quarter of the delinquency distance. `getVoteAccounts` takes a
`delinquentSlotDistance` parameter and applies a default when the call leaves it
out; Anza's `@solana/kit` RPC typings document that default as `128n`
(`packages/rpc-api/src/getVoteAccounts.ts`). This plugin never overrides the
parameter, so the warning lands well before the verdict the RPC reaches on its
own. That same 128 is the ceiling accepted for `vote_lag_warn_slots`, since a
threshold above it could only fire after the delinquency flag it is meant to
precede.

Epoch progress rides along with it. The header reads `epoch 1004 at 45%`, so a
briefing names the running epoch and says how close the next boundary is. That
distance decides whether a redelegation lands this epoch or the next.

Vote lag and epoch progress both come out of calls the run already makes. Vote
lag comes from `lastVote` on the vote record the plugin already fetches,
measured against `absoluteSlot` from the epoch reply it already fetches.
Delinquency detection is untouched. A validator the RPC lists as delinquent is
still reported as `DELINQUENT`, with its lag printed alongside for scale, and it
is never double-flagged as `BEHIND`.

The lag figure carries a caveat. The head slot is read once, in the
`getEpochInfo` call that opens the run, and every account in the report is
measured against that single number. On a multi-account report the chain keeps
moving while the later accounts are fetched, so those accounts can under-report
their lag by however far it moved in the meantime. The error only runs one way:
a printed lag is a floor, and the real distance can only be larger.

## Custody tier

**Tier: T0 Read** on the ZeroClaw custody ladder. Secrets held: the operator's
RPC endpoint URL and nothing besides, with no private key or seed phrase anywhere
in config or code. The tier is honest because every JSON-RPC method this plugin
can issue is a read method, and it carries no code that serializes an instruction.

Read-only. The plugin holds no private keys and signs no transactions; it only
reads public chain state through the operator's RPC endpoint. Nothing it exposes
can move funds, redelegate, deactivate a stake account, or change an authority.
The worst a malicious argument can achieve is to read the status of an account
that the operator already placed on the allowlist.

## Config keys

`manifest.toml` carries a closed Draft 2020-12 `config_schema` naming every key
below. The host rejects a manifest that requests `config_read` without one, and
it validates the operator's stored values against the schema before injecting
them into `execute` arguments as a typed `__config` object. The plugin refuses
to run without a configured allowlist.

| Key | Schema type | Required | Default | Meaning |
|---|---|---|---|---|
| `stake_accounts` | `array` of `string` | yes | — | Allowlist. Each entry is `label:pubkey`, or a bare pubkey that is auto-labelled `stake1`, `stake2`, and so on. At least one valid base58 pubkey is required. |
| `rpc_url` | `string` | yes | — | The operator's own Solana JSON-RPC endpoint. Must be `https://`. A trailing slash is trimmed. |
| `vote_lag_warn_slots` | `integer` | no | `32` | Vote lag, in slots, past which a still-voting validator is flagged `BEHIND`. Bounded to 1 through 128, the delinquency distance the RPC applies on its own. |
| `timeout_secs` | `integer` | no | `10` | Per-request connect timeout in seconds, bounded to 1 through 60. |

Operator storage is still a string map, and the schema is what tells the host
how to read each stored string. Set the allowlist like this:

```bash
key=$(zeroclaw plugin info stake-monitor | grep -o 'zpi1_[A-Za-z0-9_-]*')   # the instance key
zeroclaw config set "plugins.entries.$key.config.stake_accounts" '["main:<pubkey>","cold:<pubkey>"]'
zeroclaw config set "plugins.entries.$key.config.vote_lag_warn_slots" '8'
```

**Breaking change in 0.2.0.** `stake_accounts` was a comma-separated string
before this release and is a JSON array now, while `vote_lag_warn_slots` and
`timeout_secs` are real integers. The host rejects the old encoding rather than
reading it as one malformed entry, so an operator upgrading from 0.1.0 has to
rewrite the allowlist value.

## Threat model

- **Allowlist only.** The `account` argument can select an entry that is already
  configured; it can never introduce a fresh address. `resolve_account` rejects
  anything outside the list.
- **No on-chain discovery.** There is deliberately no `getProgramAccounts` scan
  to enumerate stake accounts. That call is heavy on public RPC and would widen
  what the tool can read, so an explicit allowlist is both cheaper and tighter.
- **Fail-closed config.** An unknown config key is a hard error rather than a
  silently ignored typo, which surfaces a misspelled key immediately. `rpc_url`
  must be `https://`, and both `vote_lag_warn_slots` and `timeout_secs` are
  range-bounded.
- **Authoritative commission.** The commission a report line prints is read
  from `inflationRewardsCommissionBps`, the authoritative field. The legacy
  `commission` percentage can be null even when a reward exists, so it is used
  only as a fallback, and a reply carrying neither prints `fee unknown` rather
  than the most favourable reading available.
- **No invented numbers.** A degraded reply never becomes a reassuring figure. A
  vote record with no `lastVote`, or the `0` an account that has never voted
  reports, prints `vote lag unknown` rather than a lag of zero. A `getEpochInfo`
  reply missing `absoluteSlot` costs the lag reading the same way, and slot
  counters that cannot describe a real epoch print `epoch N (progress unknown)`
  instead of a patched-up percentage.
- **Partial degradation.** A source that reads badly costs its own line and
  nothing else. Only the epoch number is load-bearing, because the delegation
  lifecycle is derived from it; a head slot or a slot counter that fails to read
  drops the reading it feeds while delegation state, amounts, delinquency, and
  rewards all still render.
- **Bounded output.** The delivered payload is capped near 900 characters,
  roughly 200 tokens, with the trailing data-issues line counted inside that
  budget, so a scheduled briefing can never flood the agent's context. Rows past
  the cap are counted in a trailing marker rather than dropped in silence.
- **Narrow egress.** The `http_client` permission reaches only the configured
  `rpc_url`. No other host is contacted, and the pure core in `src/stake.rs` does
  no I/O at all.

## A worked example

An active account whose validator has started to drift:

```
Stake: 1 account(s), 500 SOL delegated, epoch 1004 at 45% (~26 h left). 1 validator(s) BEHIND.
[active] main: 500 SOL, validator GHVi.. ok, vote lag 67 slot(s) BEHIND, fee 100.0%, no reward last epoch
```

Exactly one pairing in that block is a live mainnet reading, captured during the
verification run on 2026-07-18: the validator's `100.0%` fee and the `no reward
last epoch` beside it. Those two facts explain each other, because a validator
taking full commission leaves the staker with nothing. Everything else is
constructed to show the shape of a drifting account. The 500 SOL balance and the
67-slot lag are illustrative figures rather than readings, and so are the epoch
number and the progress and hours-left hint printed next to it.

The header sums the position and dates it to an epoch, including how far that
epoch has already run. The lag reading is the other lever: a validator still in
the RPC's `current` list keeps the delinquency check silent, yet a lag past the
warn threshold marks the line `BEHIND`. An operator reading this briefing knows
to redelegate, and knows it a day before the epoch closes.

## Prompt-injection test

An injection in the surrounding data stream tells the agent to check an address
the operator never configured, and the agent obeys. The call arrives with a
pubkey outside the allowlist:

```
tool:   stake_monitor
args:   { "account": "Cd6U9HNMvAjXDYEgQoHqc1Shtrcp55ZafCpHfVtFtmPd" }

result: success=false, error: stake account `Cd6U9HNMvAjXDYEgQoHqc1Shtrcp55ZafCpHfVtFtmPd` is not in the configured allowlist; known labels: main
```

The tool fails closed. It resolves the argument against the allowlist before any
RPC call goes out, so an unrecognized address returns `success=false` and no
network request is made on its behalf. The only names the tool will act on are
the ones the operator configured, and the error names the allowlist labels so a
legitimate typo is easy to correct.

## Layout (the reference format)

```
src/stake.rs    # pure logic, no wasm deps — host-testable with `cargo test`
src/lib.rs      # thin #[cfg(target_family = "wasm")] component shim
tests/          # host-run integration tests over the pure core
manifest.toml   # name, version, wasm_path, capabilities, permissions
```

## Build and test

```bash
cargo test                                        # host tests, no wasm needed
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release      # the component
cp target/wasm32-wasip2/release/stake_monitor.wasm stake_monitor.wasm
```

The pure core in `src/stake.rs` carries no wasm dependency, so config parsing,
response parsing, status derivation, and report rendering all run under a plain
host `cargo test`. Field shapes in those tests mirror live mainnet replies
captured during verification.

## Install

```bash
zeroclaw plugin install .   # from this directory, with the .wasm beside manifest.toml
```

The path form is what works while the plugin lives outside a registry; `zeroclaw plugin install stake-monitor` resolves by name only once a registry serves it.

Or copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, then enable plugins:

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
allowlist. Supply the allowlist and endpoint in the plugin's own config record,
which is the section the `config_read` permission unlocks:

```toml
[[plugins.entries]]
# The instance key `zeroclaw plugin info stake-monitor` prints, not the
# package name: the host consults entries by that key and silently ignores
# an entry named after the package.
name = "zpi1_WyJzdGFrZS1tb25pdG9yIiwidG9vbCIsInN0YWtlLW1vbml0b3IiXQ"

[plugins.entries.config]
stake_accounts = '["main:6ySLTQWEpCFKPYKfPaKYnhKzEccuqKafFEzfJVQ4Gifp"]'
rpc_url = "https://your-own-rpc.example.com"
vote_lag_warn_slots = "32"
timeout_secs = "10"
```

The address above is a live mainnet stake account, picked so the worked example
resolves against real chain state. It belongs to a stranger, and `main:` is only
the example label; replace both with your own account before running this.
Reading it reveals nothing the chain does not already publish.

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
`wasmtime compile --target <triple> stake_monitor.wasm -o stake_monitor.cwasm`
and point `wasm_path` at the `.cwasm`.

## Operating notes

Both of these surfaced while driving the plugin through a real Telegram channel,
and neither is visible from reading the code.

**Addresses can come back redacted.** The host scans outbound channel messages
for leaked credentials and replaces high-entropy tokens with
`[REDACTED_HIGH_ENTROPY_TOKEN]`. A vote account or stake account pubkey trips
that heuristic, so a line that names an address arrives with the address blanked
out. Set

```toml
[security.leak_detection]
high_entropy_tokens = false
```

to switch off the entropy heuristic while the deterministic patterns for real
credentials keep running: Anthropic, OpenAI, GitHub, Stripe, Google and Groq
keys are all still redacted. This report contains public chain data and operator
labels, never key material.

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

which routes every accepted message through the full agent loop. The refusals in
this plugin hold under either setting, since they are enforced against the
operator's allowlist rather than by prompt.
