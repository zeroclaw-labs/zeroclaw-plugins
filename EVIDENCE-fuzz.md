# The fuzzers, run

`just fuzz` — cargo-fuzz 0.13.2 / libFuzzer, Ubuntu 22.04, nightly.

```text
decode   Done 1051077 runs in 91 second(s)     0 crashes
policy   Done  976981 runs in 91 second(s)     0 crashes
```

Two million inputs across the two targets, no crash, no hang, no assertion
failure.

## What each target attacks

**`decode`** takes arbitrary bytes and calls the transaction decoder on them.
Solana wire format is length-prefixed and index-based, which is exactly the
shape that turns a malformed input into an out-of-bounds read: a compact-u16
length that overruns the buffer, an account index pointing past the key array,
an address-table lookup with no table. The decoder is the first thing an
attacker reaches, because it runs before any policy does.

The corpus libFuzzer converged on is worth reading — it rediscovered the
program ids on its own:

```text
"ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
"MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
```

**`policy`** drives the decision engine over arbitrary fact combinations. The
property is not "does not crash" but "the verdict is total and never upgrades":
there is no input for which the engine has no answer, and no input where
missing evidence quietly becomes REVIEW instead of DENY. Kani proves that over
the model; the fuzzer checks it against the real engine.

## The honest reading

Ninety seconds each is a smoke test, not a campaign. It is enough to say the
targets build, run, and find nothing quickly — not enough to say there is
nothing to find. `just fuzz decode 3600` is the version that would mean
something, and it has not been run for hours here.

This is why fuzzing is deliberately **not** part of `just judge`: a gate has to
terminate, and a fuzzer that terminates is a fuzzer that stopped early. The gate
runs the proofs and the arena, both of which are bounded and both of which fail
loudly.

## Reproduce

```sh
just fuzz decode 90
just fuzz policy 90
```

Linux/macOS, or WSL on Windows. Needs nightly and cargo-fuzz.
