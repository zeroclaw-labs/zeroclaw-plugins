# lending-health

A ZeroClaw **WIT component** tool plugin that reports how close an operator's
DeFi borrow positions sit to liquidation. It implements the `tool-plugin` world
from `wit/v0` and compiles to a `wasm32-wasip2` component. The tool is named
`lending_health`.

## What it does

The tool answers one question for a set of operator-owned wallets: are any
borrow positions drifting toward liquidation? A scheduled briefing or a chat
query can then surface a margin problem while there is still time to act on it.

Kamino and MarginFi arrive by different data paths. Kamino positions come from
the public Kamino REST API (`GET /portfolio/{wallet}`). MarginFi positions come
straight from on-chain account state, decoded from a `getProgramAccounts` read
over the operator's own Solana JSON-RPC endpoint, with the maintenance-weighted
asset and liability values read at fixed byte offsets. For each position the
tool computes current LTV against that market's liquidation LTV.

Position lines carry the obligation or account address they were decoded from,
shortened to a head and a tail, so a report covering several positions in the
same market says which one each figure belongs to.

Risk is measured as the **liquidation buffer**, the metric Kamino documents:
the share of collateral value that can still be lost before the position becomes
liquidatable.

    buffer = (liquidation LTV - current LTV) / liquidation LTV

Kamino's own worked example: 70% current LTV against an 80% liquidation LTV
tolerates a 12.5% decline. Thresholds are set on this basis rather than on raw
LTV because every market carries its own liquidation line. A flat 0.65 cutoff
would condemn a position with thirty points of headroom and clear one a tick from
seizure. A position at or past its line has no buffer left and always reads
`CRITICAL`.

At or below `warn_liquidation_buffer` a position reads `WARN`; at or below
`critical_liquidation_buffer` it escalates to `CRITICAL`. The defaults follow the
buffer ranges Kamino publishes for its markets, where major liquid assets carry
five to ten points between LTV and liquidation threshold and long-tail assets ten
to twenty. The report lists one line per position, worst risk first, and the
whole thing is capped near 200 tokens so a recurring briefing never floods the
agent context. Positions that the Kamino indexer has not refreshed against the
current price feed carry a staleness hint, so an old snapshot is not presented
as live. Two limits on that marker, because a marker you trust needs its edges
named: it stays silent below a six-hour skew, and it is derived from two
timestamps in the Kamino response, so a reply that stops carrying either of them
renders exactly like a fresh one. The MarginFi path has no equivalent marker at
all; its figures come from a health cache the program writes on its own schedule
and the account carries no age this reader surfaces.

`UNKNOWN` covers the case where the source gave the tool nothing to measure
against. MarginFi's risk engine zeroes the maintenance pair in its health cache
when it cannot price an account, and the initial-weight pair that remains sits
on a different basis against a different line, so it cannot stand in. Such a
position keeps the values it does carry and the marker `maint basis
unavailable`; no LTV figure is printed for it.

MarginFi's `HEALTHY` bit escapes `UNKNOWN`. The risk engine sets that bit
itself, so a cleared bit is a verdict the protocol already reached and needs no
basis of ours to be believed. That verdict travels beside the numbers rather
than inside them, which gives the condemned account two renderings. With a
maintenance pair on hand, the line prints the ratio that pair measures and
carries the marker `flagged unhealthy` after it. With the pair zeroed, the line
prints `LTV n/a` and the marker joins the `maint basis unavailable` note. Either
way the line reads `CRITICAL` and leads the report, where it stays while the
character cap drops lower-severity lines from the tail.

The verdict is only read when the engine wrote it. The same flag word carries an
`ENGINE_STATUS_OK` bit, set when the last risk check ran through. A flag word
without that bit holds whatever stood there before, down to the all-zero word an
account carries before its first check ever runs, so a cleared `HEALTHY` beside
it is the absence of a verdict. Such a position reads `UNKNOWN` with the marker
`engine status unset` and no LTV figure, because a cache nobody wrote is not
evidence either way.

Drift is deliberately out of scope. Its API does not expose a current health or
liquidation figure for an open position, so the tool would have to reconstruct
one and risk reporting a number that is simply wrong.

## Config keys

`manifest.toml` carries a closed Draft 2020-12 `config_schema` naming every key
below. The host rejects a manifest that requests `config_read` without one, and
it validates the operator's stored values against the schema before injecting
them into `execute` arguments as a typed `__config` object. The plugin can never
read the global config or another plugin's section.

| Key | Schema type | Default | Meaning |
|---|---|---|---|
| `wallets` | `array` of `string` | (required) | Allowlist. Each entry is `label:pubkey` or a bare pubkey, which is then labelled by position. The tool refuses to run with no wallet configured. |
| `rpc_url` | `string` | (none) | Solana JSON-RPC endpoint used for the MarginFi read. Required whenever `marginfi` is enabled. Must be `https://`. |
| `kamino_api_base` | `string` | `https://api.kamino.finance` | Base URL for the Kamino REST API. Must be `https://`. |
| `protocols` | `array` of `string` | `["kamino","marginfi"]` | Which protocols to query. |
| `warn_liquidation_buffer` | `number` | `0.15` | Liquidation buffer at or below which a position is flagged `WARN`. |
| `critical_liquidation_buffer` | `number` | `0.05` | Liquidation buffer at or below which a position is flagged `CRITICAL`. Must be below `warn_liquidation_buffer`: a warning fires while more of the buffer remains. |
| `timeout_secs` | `integer` | `10` | Per-request connect timeout in seconds, bounded to 1 through 60. |

Operator storage is still a string map, and the schema is what tells the host
how to read each stored string. Set the two lists like this:

```bash
key=$(zeroclaw plugin info lending-health | grep -o 'zpi1_[A-Za-z0-9_-]*')   # the instance key
zeroclaw config set "plugins.entries.$key.config.wallets" '["main:<pubkey>","cold:<pubkey>"]'
zeroclaw config set "plugins.entries.$key.config.protocols" '["kamino"]'
```

**Breaking change in 0.2.0.** `wallets` and `protocols` were comma-separated
strings before this release and are JSON arrays now. The host rejects the old
encoding rather than reading it as one malformed entry, so an operator upgrading
from 0.1.0 has to rewrite those two values. Nothing else in the config changes.
The relation between the two thresholds is still checked in the plugin, because
JSON Schema cannot state that one property must exceed another.

Kamino and MarginFi measure LTV on different bases, and both land in the same
column. Kamino publishes a protocol LTV: risk-adjusted debt over collateral,
against a per-reserve liquidation threshold. MarginFi has no equivalent figure,
so its ratio is maintenance-weighted liabilities over maintenance-weighted
assets, liquidatable at 1.0, and its lines are prefixed `maint LTV`. The dollar
amounts printed beside the ratio are on a different basis from the ratio itself:
Kamino's are its plain position values, and MarginFi's come from the health
cache's initial-weight pair, which carries the program's own confidence and
price discounts. So a MarginFi line can show $1,000 deposit, $700 borrow and
`maint LTV 75.0%` without contradicting itself, because the ratio is
maintenance-weighted and the amounts are not. The buffer normalizes the two bases, which is why one
threshold pair governs both.

## Layout (the reference format)

```
src/health.rs     # pure core: config parsing, request planning, risk classification, report rendering
src/kamino.rs     # Kamino REST path: URL building and portfolio parsing
src/marginfi.rs   # MarginFi path: getProgramAccounts body and raw account decoding
src/lib.rs        # thin #[cfg(target_family = "wasm")] component shim over the core
tests/            # host-run tests over the pure core, with live API fixtures plus one synthetic account
manifest.toml     # name, version, wasm_path, capabilities, permissions
```

The core modules above pull in no wasm dependency, so a plain host `cargo test`
covers config parsing, request planning, risk classification, and report
rendering. The wasm component reuses that same logic through the shim in
`src/lib.rs`.

## Build and test

```bash
cargo test                                        # host tests, no wasm needed
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release      # the component
cp target/wasm32-wasip2/release/lending_health.wasm lending_health.wasm
```

## Install

```bash
zeroclaw plugin install .   # from this directory, with the .wasm beside manifest.toml
```

The path form is what works while the plugin lives outside a registry; `zeroclaw plugin install lending-health` resolves by name only once a registry serves it.

Or copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, then enable plugins and configure the wallet allowlist:

```toml
[plugins]
enabled = true
# REQUIRED on every host newer than the pinned `fc8b4d83`, including 0.8.4 and
# current master: this is the only gate that admits Tool and Skill plugins, and
# it defaults to false. Without it the daemon starts clean and registers nothing.
# Inert at the pinned host, so it is safe to set either way.
auto_discover = true
```


Configuration is required here, since the plugin refuses to run without a wallet
allowlist. Supply it in the plugin's own config record, which is the section the
`config_read` permission unlocks:

```toml
[[plugins.entries]]
# The INSTANCE KEY that `zeroclaw plugin info lending-health` prints on its
# `Config entry key` line, not the package name: the host consults entries by
# that key and silently ignores an entry named after the package.
name = "zpi1_WyJsZW5kaW5nLWhlYWx0aCIsInRvb2wiLCJsZW5kaW5nLWhlYWx0aCJd"

[plugins.entries.config]
# Every value is a string. Non-string properties must CONTAIN valid JSON, so a
# list is a quoted string holding a JSON array. A bare TOML number or a
# comma-separated list is refused.
wallets = '["own:REPLACE_WITH_YOUR_WALLET_PUBKEY"]'
rpc_url = "https://REPLACE_WITH_YOUR_RPC_ENDPOINT"
kamino_api_base = "https://api.kamino.finance"
protocols = '["kamino","marginfi"]'
warn_liquidation_buffer = "0.15"
critical_liquidation_buffer = "0.05"
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
`wasmtime compile --target <triple> lending_health.wasm -o lending_health.cwasm`
and point `wasm_path` at the `.cwasm`.

## Custody tier

**Tier: T0 Read** on the ZeroClaw custody ladder. Secrets held: the operator's
RPC endpoint URL, which may carry a provider API key in its query string, and
nothing besides. No private key or seed phrase is accepted by any config key or
reachable from any code path. The tier is honest because the component carries no
transaction encoder and no submit call, so the worst outcome of a total compromise
is still a read.

The tool only reads. It builds nothing, signs nothing, holds no key material,
and moves no funds. Every call it makes is an HTTPS `GET` to the Kamino API or a
read-only JSON-RPC query to the configured endpoint. There is no code path in
the plugin that constructs a transaction, signs it, submits it, or otherwise
writes to the network, so even a fully hijacked prompt cannot cause a transfer
or a liquidation. The worst a bad instruction can do here is ask for a report
the allowlist will not produce.

## Threat model

The tool runs untrusted model output against real wallet data, so the trust
boundary sits between what the model asks for and what the plugin will actually
do.

**Address substitution.** Wallets come only from the config allowlist. The
`wallet` argument is resolved against that list by label or pubkey; anything not
on it is refused before a single request goes out. The model can narrow the
report to one configured wallet, never widen it to an arbitrary address.

**Endpoint substitution.** The RPC endpoint and the Kamino base URL live in the
operator's config, not in the tool arguments, and both are required to be
`https://`. The model cannot point the tool at an attacker-controlled host to
exfiltrate the query or receive forged position data.

**Fail-closed config.** Any unrecognized config key is a hard error, not a
silent fallback. A typo like `warn_ltw` surfaces on the first call instead of
quietly leaving the position on a default threshold, and a smuggled key never
slips through as a no-op.

**Bounded, non-leaking errors.** A failed upstream call is reported as a short
status string such as `HTTP 500`. Raw upstream response bodies from a failed
call are never appended to the report, so one wallet's broken response cannot
drag another payload into the agent context. When at least one source succeeds
the report still renders, with the failures listed as short data issues; when
every source fails the tool returns an error rather than an empty all-clear.
That failure list is written under the same character cap as the report and out
of a budget reserved inside it, so a bad day upstream trims its own list instead
of pushing the delivered payload past the bound the operator was promised.

**No invented numbers.** A liquidation distance is printed only when the source
supplied the basis it is measured on. When MarginFi's health cache comes back
with a zeroed maintenance pair, the position is reported as `UNKNOWN` with the
marker `maint basis unavailable` rather than with a ratio computed on the
initial-weight pair, which would answer a question the data did not answer.

The suppression stops at the figure: a cleared `HEALTHY` flag still classifies
the account `CRITICAL`, so a missing basis can never demote a position the
protocol already condemned. The figure is never bent the other way either. A
condemned account with a maintenance pair prints the ratio that pair measures,
since a distance floored at the liquidation line would be a stand-in number of
the same kind, printed beside a deposit and a borrow that visibly disagree with
it. And a flag word the engine never wrote condemns nothing at all: with
`ENGINE_STATUS_OK` unset the cache is unknown state, which reads `UNKNOWN`
rather than a `CRITICAL` invented from a bit nobody set.

**No custody.** As above, the plugin holds no keys and issues no writes, so a
prompt-injection ceiling is a wrong or refused report, not a lost position.

## A worked example

The report the tool renders over the captured fixtures in `tests/fixtures/`:
three open Kamino positions and one MarginFi account. The two captures were
taken from two different wallets and are stitched here under a single `demo`
label. Every figure below is decoded from those files, and
`tests/readme_example.rs` pins this exact block to the rendered output.

```
Lending health: 4 position(s), worst risk WARN.
[WARN] demo kamino Vanilla@7u3H #HcrU..iS4J: deposit $53724, borrow $40471, LTV 75.3% of 79.9% liq (positions stale 39 h)
[WARN] demo kamino Multiply@47tf #FWjx..Vq67: deposit $65030, borrow $42580, LTV 65.5% of 75.0% liq (positions stale 61 h)
[UNKNOWN] demo marginfi acct #EN1W..K7ND: deposit $860, borrow $668, LTV n/a (maint basis unavailable)
[OK] demo kamino Vanilla@47tf #6FJt..SSLy: deposit $200638, borrow $125169, LTV 62.4% of 75.0% liq (positions stale 39 h)
```

Read the first data line as: the `demo` wallet holds a Kamino `Vanilla` position
in the market whose pubkey starts `7u3H`, under obligation `HcrU..iS4J`, with
$53,724 deposited against $40,471 borrowed. Its LTV of 75.3% is close to the
79.9% liquidation LTV, so it is flagged `WARN`. The trailing hint says the Kamino
indexer's position snapshot lags the price feed by 39 hours, so the figure is a
recent read rather than a live one. The header names the count and the worst
status up front, which is the part a scheduled briefing surfaces first.

The MarginFi account on the `UNKNOWN` line was captured with a zeroed
maintenance pair, so the tool prints the values it read and stops there. No
percentage appears on that line, because none of the numbers on hand measures
how far the account sits from its liquidation line.

## Prompt-injection test

Suppose the model is talked into ignoring the operator and querying a wallet
that was never configured. The allowlist stops it cold:

```
args:   {"wallet":"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"}
        config allowlist has only demo:AcNSmd5C...

result: success=false
error:  wallet `9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM` is not in the
        configured allowlist; known labels: demo
```

The refusal is not a policy prompt or a soft warning. The wallet allowlist is
resolved inside the plugin before any network call, so an address that is not in
the operator's config has no path to a request. Even if the model fully complied
with the injection and passed the attacker's pubkey, the tool physically cannot
query it. The failure is closed, and the error names only the labels the
operator actually configured.

## Operating notes

Both of these surfaced while driving the plugin through a real Telegram channel,
and neither is visible from reading the code.

**Addresses can come back redacted.** The host scans outbound channel messages
for leaked credentials and replaces high-entropy tokens with
`[REDACTED_HIGH_ENTROPY_TOKEN]`. A Solana pubkey trips that heuristic, so a
refusal that names an address arrives with the address blanked out. Set

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
