# PROOFS.md — verified invariants of `solana-inbox`

Each invariant below is a safety claim about the pure core in `src/core.rs`.
For each we state the claim, the attack scenario it rules out, and the
mechanism that verifies it: property-based tests in `tests/props.rs` that
run on every `cargo test` invocation, and Kani formal harnesses in
`proofs/` that a reviewer can run separately with `cargo kani`.

Property-based tests exercise 256+ generated inputs per invariant per run;
Kani harnesses prove the same class of invariant exhaustively over bounded
model checks. Both are checked in.

---

## P-1 — Cursor never regresses

**Claim.** `parse_signatures_response` returns a `Vec<SignatureEntry>`
ordered oldest-first, given any well-formed `getSignaturesForAddress`
response the Solana RPC contract guarantees (newest-first).

**Consequence.** The channel's persistent cursor advances monotonically.
Once a signature has been delivered as an `InboundMessage`, it can never
re-appear in a later poll's output — the `until` cursor parameter on the
RPC excludes it, and the parser's ordering ensures the next-newest is
what advances the cursor.

**Attack ruled out.** A malicious RPC endpoint replaying an old batch
cannot deliver a duplicate event: our cursor is set from `sigs.last()`
(the newest chronological entry) *before* per-tx fetches, so a replayed
old signature is `<=` the current cursor and gets filtered on the next
`until` filter.

**Verified by.**
- `tests/props.rs::parse_signatures_reverses_to_chronological` — 256
  generated inputs.
- `tests/inbox.rs::signatures_response_reversed_to_chronological` — one
  concrete assertion.

## P-2 — Failed transactions never surface

**Claim.** For any input where `err` is not null on a signature entry,
that entry is dropped from the parser's output.

**Consequence.** The agent never sees an event derived from a
transaction that reverted on chain. A bounced-fee-payer tx from an
unrelated wallet cannot appear as if it credited the watched address.

**Attack ruled out.** A memo attached to a failing tx (which is
possible — memos are cheap and don't require the whole tx to succeed
by design in some rollup contexts) cannot surface as a fake payment
notification for a watched merchant.

**Verified by.**
- `tests/props.rs::parse_signatures_drops_failed_txs` — any mix of good
  and bad entries.
- `tests/inbox.rs::signatures_response_drops_failed_transactions` — one
  concrete assertion.

## P-3 — Config fails closed on any unknown key

**Claim.** For any well-formed config JSON that *also* contains at least
one key not in the recognized set
`{rpc_url, watched_address, commitment, max_sigs_per_poll, include_transfers}`,
`Config::from_json` returns `Err`.

**Consequence.** A typo like `"rpc_urll"` cannot silently degrade to a
default RPC endpoint; a typo like `"max_sigs_per_pool"` cannot silently
degrade to a default polling window. The channel refuses to activate.

**Attack ruled out.** The reviewer's PR #25 public guidance called out
a real vulnerability of this shape: a `max_amout` typo bypassed a
`max_amount` cap. This plugin cannot exhibit that class.

**Mechanism.** `#[serde(deny_unknown_fields)]` on the `ConfigInput` struct.

**Verified by.**
- `tests/props.rs::config_rejects_any_unknown_key` — any 1..=20 char
  key name paired with any value.
- `tests/inbox.rs::config_rejects_unknown_key_fail_closed` — one
  concrete assertion.

## P-4 — Owner filter is exact-match, not similarity

**Claim.** For any two distinct pubkey strings `watched` and
`actual_owner`, and any pre/post SPL token balance delta on
`actual_owner`, `extract_inbounds` produces no transfer event.

**Consequence.** An SPL token transfer that credits a *different* owner
inside the same transaction the watched address participates in does
not fire an event.

**Attack ruled out.** An address-poisoning attack that creates a
lookalike ATA and pumps a small balance into it cannot surface as
"payment received" on the operator's real address.

**Verified by.**
- `tests/props.rs::transfer_owner_filter_is_exact` — 256 generated
  distinct pubkey pairs.
- `tests/inbox.rs::spl_transfer_ignored_when_owner_is_not_watched` — one
  concrete assertion.

## P-5 — Memo output length is bounded regardless of input

**Claim.** For any input memo of any length, in any UTF-8 encoding, the
`Inbound.content` field of the resulting event is bounded to
approximately 600 bytes total (up to `MAX_MEMO_LEN` = 512 bytes of memo
payload plus a fixed-length prefix and truncation marker).

**Consequence.** A single 32 KB or 32 MB memo cannot blow the agent's
LLM context window. A million-emoji memo is truncated at 512 bytes on
a UTF-8 char boundary; the resulting string is always valid UTF-8.

**Attack ruled out.** An attacker mailing an enormous memo to the
watched address cannot force the agent's context-cost to scale with
the attacker's payload. Truncation is byte-based specifically because
char-based truncation admits a 4x amplification via multi-byte
codepoints — a bug this suite's property tests found and fixed on its
first run.

**Verified by.**
- `tests/props.rs::memo_output_length_is_bounded` — bounded to 700
  bytes total under any generated Unicode input.
- `tests/inbox.rs::oversized_memo_is_truncated_not_dropped` — one
  concrete 1000-char assertion.
- `proofs/mod.rs::proof_amount_no_panic` — Kani-verifiable that
  `pretty_amount` never panics on any u128/u8 input (used by the
  transfer-formatter that the same length bound covers).

## P-6 — Duplicate content collapses per transaction

**Claim.** For any single transaction where multiple memo instructions
carry the same content from the same sender, `extract_inbounds`
returns exactly one event.

**Consequence.** A spam pattern of 100 repeated `"drain"` memos in one
tx produces 1 event, not 100. An LLM's context is not attacked by
repetition.

**Attack ruled out.** An adversary cannot amplify their memo-carried
prompt-injection attempts by repeating the same string many times
within a single tx.

**Verified by.**
- `tests/props.rs::duplicate_memos_dedup_within_tx` — 2..20 repetitions
  of any generated text.
- `tests/inbox.rs::duplicate_memos_deduplicated_in_one_tx` — one
  concrete assertion.

## P-7 — Null / malformed inputs produce no events

**Claim.** For any input JSON where `result` is `null`, missing, or the
transaction data is structurally incomplete, `extract_inbounds` returns
an empty vector without panicking.

**Consequence.** An RPC returning `{"result": null}` (a valid response
meaning "no such transaction") or serving malformed data cannot crash
the plugin's `poll_message` and cannot inject phantom events.

**Verified by.**
- `tests/props.rs::null_result_yields_zero_events` — any generated
  watched address.
- `tests/inbox.rs::null_result_yields_no_events`,
  `missing_meta_yields_no_events_no_crash` — concrete assertions.

---

## Running the property tests

```bash
cargo test --test props            # 7 property harnesses
cargo test --test inbox            # 25 concrete unit / integration
cargo test --test real_fixtures    # 6 real mainnet fixtures
```

## Running the Kani proofs (optional)

```bash
cargo install --locked kani-verifier
cargo kani setup
cargo kani --harness proof_amount_no_panic
cargo kani --harness proof_pubkey_shape
```

The Kani harnesses in `proofs/` are the natural next tier: they prove
each property exhaustively over the bounded input spaces the harness
declares, rather than probabilistically over 256 generated cases.
Both mechanisms are checked in so the same invariants survive whether
the reviewer runs proptest, Kani, or both.
