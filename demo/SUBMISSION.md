# Safe Hands — submission checklist

## Done
- [x] 3 components + core, wasip2, pure-core/thin-shim, host tests, MIT
- [x] just prove-safety green (tests + 20 attack fixtures + clippy host/wasm + builds)
- [x] Byte-exact goldens (web3.js + official Squads SDK)
- [x] Live 3-tool flow on devnet + on-chain execute (EVIDENCE.md)
- [x] READMEs (root EN + PT-BR + 3 plugins), personas, demo config
- [x] Draft PR: https://github.com/zeroclaw-labs/zeroclaw-plugins/pull/112
- [x] Demo script: demo/DEMO-SCRIPT.md (all commands pre-verified live)

## User to do (the human-only parts)
1. **Record the video** (≤3 min) per demo/DEMO-SCRIPT.md — terminal + phone.
   All four acts were run live today; commands are copy-paste ready.
2. **Submit on Superteam Earn** with: PR link + video + EVIDENCE.md +
   the write-up (root README sections: custody, threat model, what fought us).
3. **Post the X build-log** (draft below) — tiebreak.
4. **Join the ZeroClaw Discord #solana-bounty** (Thu 8pm EST call) — intro +
   link to PR #112; ask Jordan to approve the CI run (it's action_required
   for first-time contributors).
5. **Rotate the Twitter session token** you pasted earlier.

## X post draft (build in public)

Day 1 of building Safe Hands for the @zeroclawlabs × @SuperteamBR Solana bounty 🦀

AI agents can already move money. Nobody asks whether they should.

Safe Hands: a 3-component wasm32-wasip2 suite that sits between the agent and the funds:

🔍 solana-tx-authorize — decode → intent-match → policy → simulate → ALLOW/REVIEW/DENY/UNKNOWN
🔨 spl-transfer-build — unsigned transfers that refuse policy violations at build time
🛡 squads-proposal-build — re-verifies EVERYTHING itself before proposing. Forge a prior ALLOW and it refuses: SH-TRUST-FORGED

The agent proposes. A Squads multisig disposes. The agent never holds a key.

Already live: full flow on devnet ending in an executed multisig payout (0.05 SOL, on-chain). 20-fixture attack arena runs offline in one command: just prove-safety

PR #112 → github.com/zeroclaw-labs/zeroclaw-plugins/pull/112
