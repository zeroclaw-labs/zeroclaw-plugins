# Live read-only test results

Date: 2026-07-17. Each report was fetched with `GET https://api.rugcheck.xyz/v1/tokens/<mint>/report` and passed to the plugin's host-run pure core (`cargo run --example assess_rugcheck`). No credentials, signing, or write requests were used. Word count is whitespace-delimited output words.

## 1. USDC — `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`

Expected by the task as a familiar clean asset; actual conservative output was **RED** (26 words):

```text
RED - Solana token risk: RED
Mint: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
- mint authority remains active (supply can change)
- freeze authority remains active (accounts can be frozen)
Read-only assessment; not financial advice.
```

Finding: the live RugCheck response supplied non-null authority objects. The original parser only recognised strings; this was fixed to treat any non-null authority shape as active (fail closed), with a regression fixture. No stablecoin allowlist was added.

## 2. High concentration / danger example — `6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN`

**RED**, 22 words:

```text
RED - Solana token risk: RED
Mint: 6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN
- top holder controls 76.3% of supply
- top 5 holders control 84.9%
Read-only assessment; not financial advice.
```

This is a known RugCheck danger/concentration example; the live response exercised percentage parsing.

## 3. Token-2022 transfer-fee mint — `CKfatsPMUf8SkiURsDXs7eK6GWb4Jsd6UDbs7twMCWxo`

**RED**, 15 words:

```text
RED - Solana token risk: RED
Mint: CKfatsPMUf8SkiURsDXs7eK6GWb4Jsd6UDbs7twMCWxo
- Token-2022 transfer fees enabled
Read-only assessment; not financial advice.
```

The live RugCheck `token_extensions.transferFeeConfig` contained current fee configuration. The core now parses this fallback and has a matching fixture. No `HELIUS_API_KEY` was available in the environment, so a live Helius `mint_extensions` response could not be requested without violating the no-hardcoded-key rule. The WASM code path for Helius remains covered by compilation; rerun this case with a user-provided config key before submission.

All observed outputs were far below the ~200-token limit; the automated worst-case test enforces the bound.
