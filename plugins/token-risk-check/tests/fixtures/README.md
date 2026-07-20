# Test fixtures — real mainnet accounts

Each `*_account.json` is a verbatim `getAccountInfo` (base64 encoding) response
captured from `https://api.mainnet-beta.solana.com`, replayed by the tests in
`tests/risk.rs` so the hand-rolled raw mint-layout and Token-2022 TLV parsers
are proven against real on-chain extension bytes rather than synthetic ones.
No network access is used at test time; `cargo test` runs fully offline.

| Fixture | Mint | Proves |
|---|---|---|
| `usdc_account.json` | `EPjFWdd5…Dt1v` | legacy spl-token, both authorities live → AMBER |
| `wsol_account.json` | `So1111…1112` | native SOL wrapper special-case, authorities revoked |
| `pyusd_account.json` | `2b1kV6Dk…4GXo` | dense Token-2022: permanent delegate + close authority + confidential transfers + mutable metadata + dormant transfer hook → RED |
| `bern_account.json` | `CKfatsPM…CWxo` | Token-2022 with a live transfer fee, decoded to real basis points |

Captured 2026-07-21. On-chain state can change (e.g. an authority being
revoked); if an assertion drifts, re-capture with:

    curl -s -X POST -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["<MINT>",{"encoding":"base64","commitment":"confirmed"}]}' \
      https://api.mainnet-beta.solana.com > <name>_account.json
