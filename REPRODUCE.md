# Reproduce this in an evening

Two paths. The first proves every safety claim offline in about five minutes
and needs no wallet, no RPC key, and no network. The second runs the live
merchant desk on devnet.

## Part 1 — prove the safety claims (5 minutes, offline)

Requirements: Rust 1.96.1+ and `just`. Nothing else. No network, no keys.

```sh
git clone <this-repo> && cd zeroclaw-plugins
rustup target add wasm32-wasip2
just prove-safety
```

That single command runs:

- every host test across the core and all four plugins (RPC is mocked);
- the attack arena in `conformance/fixtures/` — each fixture drives the **real**
  plugin entry points and asserts the verdict and reason codes;
- `clippy -D warnings` on the host **and** `wasm32-wasip2` targets;
- release builds of all four `wasm32-wasip2` components.

Exit code 0 means every claim in this repository's READMEs is currently true on
your machine. If it exits non-zero, a claim is broken — please open an issue.

To watch only the attack arena, including the refund-redirect and
amount-inflation attempts:

```sh
cargo run --locked --release --manifest-path conformance/Cargo.toml
```

Everything in Part 1 uses mocked RPC. It is deterministic proof of the decision
logic, **not** a live-chain claim.

## Part 2 — run the merchant desk (devnet)

### 2.1 Build a host that can load plugins

Plugins are not in the release binaries. That is the one genuinely
time-consuming step here, so start it first — it takes 10–20 minutes on a cold
cache.

```sh
git clone https://github.com/zeroclaw-labs/zeroclaw && cd zeroclaw
cargo build --release --features plugins-wasm-cranelift
```

### 2.2 Stage and install the components

Back in this repository:

```sh
just stage-local
zeroclaw plugin install ./dist/local/payment-verify
zeroclaw plugin install ./dist/local/spl-transfer-build
zeroclaw plugin install ./dist/local/solana-tx-authorize
zeroclaw plugin install ./dist/local/squads-proposal-build
zeroclaw plugin list
```

### 2.3 What you need to supply

| Thing | Why | How |
|---|---|---|
| Telegram bot token | The operator channel | @BotFather |
| Your Telegram user ID | The inbound allowlist | @userinfobot |
| A merchant wallet address | Receives invoice payments | any wallet, devnet |
| Two **independent** devnet RPC URLs | One endpoint is not evidence | `https://api.devnet.solana.com` plus any provider's devnet endpoint |
| Devnet USDC | To pay a test invoice | [faucet.circle.com](https://faucet.circle.com) |
| A Squads v4 multisig | Human approval of refunds | [v4.squads.so](https://v4.squads.so) on devnet |

No private key is ever placed in config. If a step asks you for one, you are
doing something this design does not require.

### 2.4 Configure

Copy `examples/zeroclaw-config.merchant.toml` into your ZeroClaw config and
replace every `<PLACEHOLDER>`. The two that matter most:

- `peer_groups.merchant_desk.external_peers` — **only** your Telegram user ID.
  `["*"]` would hand every customer the operator's tools.
- `invoice_salt` — any random string, but it must be identical everywhere and
  must never change. References are derived from it; changing it orphans every
  open invoice.

Then install the skill and SOPs:

```sh
zeroclaw skills bundle add merchant
cp -r skills/merchant-desk <install>/shared/skills/merchant/
cp -r sops/invoice-watch sops/refund-approval <install>/workspace/sops/
zeroclaw sop validate invoice-watch
zeroclaw sop validate refund-approval
```

`invoice-watch` uses a cron trigger. Cron fan-in requires SOP audit logging
enabled and a non-zero SOP maintenance interval; without both, the procedure
loads but never fires on its own and you must run it with
`zeroclaw sop execute invoice-watch`.

### 2.5 Drive it

In your operator chat:

```text
charge order A-1042 for 25 USDC
```

The agent returns a Solana Pay link. Pay it from a second devnet wallet, then:

```text
check A-1042
```

You should see `PAID` with the signature and both amounts.

### 2.6 Prove it fails closed

Ask for a refund to an address that is **not** in `allowed_recipients`:

```text
refund A-1042 to <some other address>
```

`solana-tx-authorize` denies it on the exact bytes and no proposal is created.
That denial is the product. Fixtures 22 and 23 assert the same behaviour
offline, so you can see it without spending anything.

## Optional — durable nonce

A recent blockhash dies in roughly 90 seconds, which is shorter than a human
takes to approve a refund. To make a refund survive the approval queue, create
a nonce account and opt in **twice** — the builder alone is not enough:

```sh
solana-keygen new -o nonce.json
solana create-nonce-account nonce.json 0.0015 --url devnet
```

1. Set `nonce_account` and `nonce_authority` in the `spl-transfer-build` config.
2. Add the nonce address to `allowed_nonce_accounts` **and** add
   `advance_nonce` to `allowed_instructions.system` in every `policy_json`.

Miss either and the build is refused, which fixture 11 (refused) and fixture 21
(allowed) demonstrate side by side.

## Troubleshooting

**`just prove-safety` fails on the wasm target** — run
`rustup target add wasm32-wasip2`.

**The agent cannot see the tools** — `mcp_bundles`/plugin config changes take
effect on session restart, and `allowed_tools` in the risk profile must list
each plugin by name.

**`payment-verify` returns UNKNOWN** — that is the fail-closed path, not a bug.
It means the two RPC endpoints disagreed or one returned something malformed.
Check both URLs. `UNKNOWN` never means unpaid.

**The bot ignores you** — `external_peers` must contain your numeric Telegram
user ID, and peer-group changes require a daemon restart.
