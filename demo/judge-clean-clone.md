# A judge's clean clone, verified cold

Not our working tree. A fresh `git clone --depth 1` of
`github.com/Pratiikpy/zeroclaw-plugins` at branch `safe-hands`, on a machine
with nothing cached, running `just judge --network` start to finish.

Timings are a cold build. A second run is roughly 90 seconds.

```text
  SAFE HANDS — JUDGE SCORECARD
==============================================================
  commit    3bdae2b
  toolchain rustc 1.96.1 (31fca3adb 2026-06-26)
  date      2026-08-06T00:39:50Z
--------------------------------------------------------------
  Each row is a claim and the command that could falsify it.
--------------------------------------------------------------

  PASS  the logic is tested, not asserted                    (143s)
  PASS  every attack fixture still fails closed              (37s)
  PASS  a verdict can be re-derived from its receipt         (1s)
  PASS  the decision log is internally honest                (0s)
  PASS  no component imports what it never declared          (58s)
  PASS  the shipped .wasm refuses in a real runtime          (227s)
  PASS  no known vulnerable dependency ships                 (18s)
  PASS  it builds clean for wasm32-wasip2                    (2s)
  PASS  the source is warning-free on both targets           (258s)
  PASS  the log matches its anchor published on Solana       (5s)
  SKIP  the policy model is machine-checked                   needs Kani (Linux/macOS): just prove

--------------------------------------------------------------
  WHERE THE RUBRIC IS ANSWERED
--------------------------------------------------------------
  use case 30%        the 58s run: youtu.be/63E0zhGNnxQ
                      verbatim transcript: demo/live/telegram-2026-08-05.md
  safety/custody 25%  every tier T0 or T1, no signing key anywhere
                      README "What Safe Hands still trusts" names what is left
                      arena + receipt + log rows above
  craft 20%           pure core / thin shim, host tests with mocked RPC,
                      kani + fuzz + mutation + differential decoder tests
  reproducibility 15% REPRODUCE.md, and this scorecard
  showcase 10%        README claims table, EVIDENCE.md on-chain record

==============================================================
  RESULT: 10 passed, 1 skipped, 0 failed — the guard holds.
==============================================================

```
