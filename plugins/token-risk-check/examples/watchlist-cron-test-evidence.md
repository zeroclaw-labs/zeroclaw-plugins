# Local cron delivery test

Tested locally on 2026-07-19 with ZeroClaw 0.8.3 and the existing Telegram binding.

1. The declarative job was temporarily configured as `every_ms = 60000`.
2. The scheduler executed it as agent `rugbuster_zeroclaw` with `allowed_tools = ["token_risk_check"]` and `uses_memory = false`.
3. The persisted run was `status=ok`; the announce delivery used `channel=telegram`, the configured chat ID, and `best_effort=false` (therefore a failed delivery would have marked the run failed).
4. The returned report was delivered as a compact Telegram message and recorded this result:

```text
Daily Token-Risk Watchlist
Mint: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
Verdict: RED
Key risks: mint authority remains active; freeze authority remains active.
```

The configuration was then restored to `0 8 * * *` with `tz = "Europe/Belgrade"`; the next run is 08:00 local time. No shell, filesystem, browser, host HTTP, or other agent tool is granted to the job.
