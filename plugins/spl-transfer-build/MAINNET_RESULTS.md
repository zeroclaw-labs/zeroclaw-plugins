# Mainnet-beta read-only validation

**Verdict: PASS.** The plugin's read-only paths were exercised live against
`https://api.mainnet-beta.solana.com` through the real ZeroClaw 0.8.3 WASM host.
A real mainnet USDC transfer was constructed, verified, and **simulated on
mainnet with `err: null`**, and independently decoded by a separate library. A
real mainnet Token-2022 mint was refused, twice, for two different reasons.

**Nothing was signed. Nothing was submitted. No private key for any address in
this document exists in this project, in any config, or in any committed file.**
The plugin is T1: it has no signing path and no submission path at all, which is
exactly why pointing it at mainnet is safe.

Recorded: 2026-07-30. Cluster `mainnet-beta`, `solana-core 4.1.0`,
feature set `3345198602`. Host `zeroclaw 0.8.3` (Cranelift/Wasmtime plugin host).
Component built with `cargo +1.96.1 build --locked --target wasm32-wasip2
--release` from `nanosol` rev `5d9501408346540332e95611219a15dafd9c2d87`.

## Why mainnet, and what it does and does not prove

Devnet proves the whole lifecycle including execution (see `M4_RESULTS.md`:
a finalized devnet transfer after a 363-second hold). Devnet cannot prove the
read paths behave against **real** mint state — real Token-2022 extension TLV
layouts, real canonical ATAs, real compute costs. Mainnet proves that, and it
can be done with zero risk precisely because the custody tier forbids signing.

This document therefore claims: **the read, construct, verify, and simulate
paths are correct against live mainnet state.** It does not claim any mainnet
transfer was executed, because executing one would require a key the project
refuses to hold.

## Addresses used

All are public mainnet addresses. They were selected by reading recent public
USDC activity — no relationship to this project, and no key for any of them
exists here. They are read-only construction inputs supplied through **operator
config**, never by the model.

| Role | Address | Note |
|---|---|---|
| `sender_pubkey` (operator config) | `F7p3dFrjRTbtRp8FRF6qHLomXbKRBzpvBLjtQcfcgmNe` | on-curve wallet holding USDC; needed so mainnet simulation is meaningful |
| recipient (allowlisted) | `4kYMh3RoXaiwdwXw6NkJTaowMkgq3oNoSGNZh9Y3RG4K` | on-curve wallet with an existing USDC ATA |
| mint — legacy SPL | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` | USDC; owner `Tokenkeg…`, 82 bytes, 6 decimals, no extensions |
| mint — Token-2022 | `2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo` | PYUSD; owner `TokenzQd…`, 866 bytes, 6 decimals |

The Token-2022 mint carries eight real extensions — `mintCloseAuthority`,
`permanentDelegate`, `transferFeeConfig`, `confidentialTransferMint`,
`confidentialTransferFeeConfig`, `transferHook`, `metadataPointer`,
`tokenMetadata`. This is the live TLV data the policy has to decide against, not
a fixture.

## Case 1 — legacy SPL mint, full success path (live mainnet)

Driven through `zeroclaw agent -a m5` by the deterministic oracle
`tests/host_chat_mock_mainnet.py --expect ok`. The component was discovered with
capability `Tool` and permissions `HttpClient, ConfigRead`.

Host result:

```
MAINNET_AGENT_OK reference=HJq1JwBQkEBTh9s32QskfMHu1WYYSYjNa81m1GJXbhap
                 last_valid_block_height=414167454
                 transaction_bytes=485
                 transaction_sha256=252ad70f25d78fdab491117fa4fcb3faf26e30ff191de0afaa2515b7406cffa4
```

The component made real mainnet JSON-RPC calls (mint `getAccountInfo`,
`getLatestBlockhash`, `simulateTransaction`) and returned a 485-byte unsigned
transaction. Because the plugin refuses to return a transaction whose simulation
fails, `MAINNET_AGENT_OK` already implies the plugin's own mainnet simulation
succeeded — but that was not taken on trust; see Case 2.

## Case 2 — independent decode and independent mainnet simulation

`tests/mainnet_inspect.py` re-checks the exact returned bytes using `solders`
(an independent implementation, not the plugin's verifier) and re-simulates them
against mainnet itself. The script has **no keypair argument and no signing
path**.

| Check | Result |
|---|---|
| `transaction_bytes` | `485` |
| `transaction_sha256` | `252ad70f25d78fdab491117fa4fcb3faf26e30ff191de0afaa2515b7406cffa4` |
| re-serialize is byte-identical | ✅ |
| signature slots / all zero | `1` / ✅ — nothing is signed |
| message is v0 | ✅ |
| required signers | `1` |
| address table lookups | `0` |
| fee payer == configured sender | ✅ |
| derived sender ATA | `Q4UmPB9hKMw3ERqksavS9oEpNo2eWG4ffkWg7wHa9j6` |
| derived recipient ATA | `4qsJJZgr2Rv8FgUR37uXPJvRcP3RUEB1a4mLbHsWLwr2` |
| instruction programs | `ATokenGPv…`, `Tokenkeg…`, `MemoSq4g…` |
| ATA instruction is `CreateIdempotent` (`01`), targets recipient ATA | ✅ / ✅ |
| token instruction discriminant | `12` (`TransferChecked`) |
| amount raw / decimals | `1500000` / `6` — both match `1.50` at 6 decimals |
| source == sender ATA, mint == configured mint, destination == recipient ATA, authority == sender | ✅ ✅ ✅ ✅ |
| memo text matches | ✅ |
| `message_sha256` | `f5cd2ae1a99a2dae7b3db09e1b27d42596d27c44a12d95d802c667ca097d860d` |
| **independent mainnet `simulateTransaction`** (`sigVerify=false`) | **`err: null`**, `unitsConsumed: 22853`, 11 log lines |

```
INDEPENDENT_MAINNET_INSPECTION_OK
```

### A free mainnet oracle for ATA derivation

`nanosol` derives associated token accounts with hand-rolled sha256 + off-curve
detection, because `solana-sdk` does not build for `wasm32-wasip2`. Mainnet
supplies an independent check on that: the derived sender ATA
`Q4UmPB9hKMw3ERqksavS9oEpNo2eWG4ffkWg7wHa9j6` **is** the token account that
actually holds this wallet's USDC on chain, and the derived recipient ATA
`4qsJJZgr2Rv8FgUR37uXPJvRcP3RUEB1a4mLbHsWLwr2` likewise. Four out of four
candidate wallets sampled from live USDC activity had their real on-chain token
account equal to the independently derived canonical ATA.

## Case 3 — real mainnet Token-2022 mint, refused twice

Same host, same live mainnet endpoint, `--expect refusal`. Both runs returned
**no transaction at all**; the oracle asserts the absence, not just an error
string.

| Config | Host result | Refusal reason (bounded, model-visible) |
|---|---|---|
| `allow_token_2022 = "false"` (default) | `MAINNET_REFUSAL_OK no_transaction_returned` | `Token-2022 mint refused; operator must explicitly enable extension-free Token-2022` |
| `allow_token_2022 = "true"` (operator opt-in) | `MAINNET_REFUSAL_OK no_transaction_returned` | `Token-2022 mint extensions are outside the supported safe subset` |

The second row is the one that matters. With Token-2022 explicitly enabled by
the operator, the plugin still refused — because it walked the **real** mainnet
TLV extension list and found extensions (`transferFeeConfig`,
`permanentDelegate`, `transferHook`, confidential-transfer) outside the
supported safe subset. A transfer fee or a permanent delegate can make the
amount a human approves differ from the amount a recipient receives, which is
precisely the deception the whole design exists to prevent. Fail-closed against
live data, not against a fixture.

## Reproducing this

Read-only; costs nothing; moves nothing.

```bash
cd plugins/spl-transfer-build
cargo +1.96.1 build --locked --target wasm32-wasip2 --release
# install manifest + wasm into a disposable ZeroClaw config dir, set
# rpc_url = "https://api.mainnet-beta.solana.com" and the addresses above,
# then:
python3 tests/host_chat_mock_mainnet.py --port 38191 \
  --recipient 4kYMh3RoXaiwdwXw6NkJTaowMkgq3oNoSGNZh9Y3RG4K \
  --mint USDC --amount 1.50 --memo "mainnet read-only construction" \
  --invoice-id mainnet-readonly-2026-07-30 --expect ok &
zeroclaw --config-dir <disposable> agent -a m5 \
  -m "Build a guarded USDC transfer of 1.50 to the allowlisted recipient."

# then verify the bytes with an independent library and re-simulate:
python3 tests/mainnet_inspect.py --transaction <captured.b64> \
  --rpc-url https://api.mainnet-beta.solana.com \
  --sender F7p3dFrjRTbtRp8FRF6qHLomXbKRBzpvBLjtQcfcgmNe \
  --mint EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v \
  --recipient 4kYMh3RoXaiwdwXw6NkJTaowMkgq3oNoSGNZh9Y3RG4K \
  --amount-raw 1500000 --decimals 6 --memo "mainnet read-only construction"
```

`mainnet_inspect.py` needs `solders` and `httpx`. The transaction's recent
blockhash expires in ~60–90 s, so a captured fixture can be decoded and
structurally re-checked indefinitely but can only be *simulated* while fresh —
rebuild to re-simulate.

## `solana-pay-request` on mainnet

Not applicable, and deliberately so: `solana-pay-request` declares
`config_read` only, imports no `wasi:http`, and makes no network call on any
cluster. It composes a mainnet-usable Solana Pay URL for a mainnet mint without
ever contacting a mainnet endpoint — the cluster is the wallet's concern, not
the plugin's.

## Residual notes

- The configured RPC endpoint remains a trust boundary on mainnet exactly as on
  devnet: a dishonest endpoint can misreport mint state. What the plugin
  guarantees is that the returned bytes are internally consistent with the state
  it accepted, and that the approval summary is derived from those bytes.
- Case 1's success depends on the sampled sender still holding USDC and its ATA
  still existing. If a future reproduction picks a wallet that has since moved
  its balance, mainnet simulation fails and the plugin refuses — which is the
  correct behavior, not a regression.
- Mainnet compute usage (`22853` CU) is recorded as an observation. No
  compute-budget instruction is set; devnet execution showed none is required.
