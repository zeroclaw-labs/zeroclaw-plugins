# Real mainnet fixtures

Four `getTransaction` responses captured verbatim from
`https://api.mainnet-beta.solana.com` on **2026-07-25** with
`encoding: "jsonParsed"`, `maxSupportedTransactionVersion: 0`,
`commitment: "confirmed"|"finalized"`. Used by
`tests/real_fixtures.rs` to prove the parser handles production
JSON shapes the hand-crafted fixtures don't stress.

| File | Kind | What it stresses |
|---|---|---|
| `real_meteora_dlmm.json` | Meteora DLMM swap | 63 static accountKeys, ComputeBudget instructions, custom aggregator program (`Fibo6vWH…`), 20-entry token-balance arrays |
| `real_usdc_activity.json` | USDC-adjacent transfer | 40 accountKeys, dense preTokenBalances/postTokenBalances, custom pool program (`FkKYVSiM…`) |
| `real_custom_program.json` | Opaque protocol activity | 50 accountKeys, only ComputeBudget + custom program (`3QUnrcMq…`), no memos, no watched-address involvement |
| `real_durable_nonce_lut.json` | Durable-nonce versioned tx | Address lookup tables in play — `accountKeys` is a mix of static and LUT-loaded refs, the historically parser-hostile combination |

## To refresh

```bash
# Pick a live signature from any active address.
sig=<signature>
curl -sS -X POST -H "Content-Type: application/json" \
  https://api.mainnet-beta.solana.com \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransaction\",\"params\":[\"$sig\",{\"encoding\":\"jsonParsed\",\"maxSupportedTransactionVersion\":0,\"commitment\":\"confirmed\"}]}" \
  | python3 -m json.tool > tests/fixtures/<name>.json
```

Fixtures are checked in verbatim so the tests are reproducible offline
and independent of any live RPC endpoint's rate limits or availability.
