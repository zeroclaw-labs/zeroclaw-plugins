# One-command demo

Everything here runs from a clean clone with no credentials and no network beyond
localhost. It prints real counts rather than a green tick, so you can check the
numbers instead of trusting them.

```
bash demo/run-demo.sh
```

Wall clock is about two minutes on a cold clone and about 17 seconds warm.

## What the stages do

1. **Build.** Compiles the three components for `wasm32-wasip2` and prints the byte
   size of each one.
2. **Test.** Runs every component suite plus the shared `solana-core` suite and
   prints the passing count per component.
3. **End to end against a local fake.** Starts `demo/fake-rpc.py` on localhost and
   drives the real compiled components through 18 scenarios: three that build an
   unsigned transaction, nine that refuse, seven of those refusing before any RPC
   call at all. The scenario outputs are diffed against `demo/golden/local-fake.json`
   and the run fails if a single line drifts. Every request and response the
   components saw is written to `demo/out/`, and a reference copy of one run is
   committed under `demo/artifacts/local-fake-run/`.
4. **Mainnet read path.** Off by default, because it is the only stage that leaves
   localhost. Enable it with `MAINNET=1 bash demo/run-demo.sh`.

## The mainnet stage, and exactly what it proves

It points the real components at a public mainnet RPC read-only, then asks mainnet
to simulate an unsigned transaction the builder produced. `simulateTransaction`
never broadcasts, so this costs nothing, moves nothing and needs no key.

A captured run is committed under `demo/artifacts/mainnet-readpath/`, request and
response bodies included, with `getGenesisHash` in the record so you can confirm the
cluster was mainnet-beta rather than a devnet endpoint someone relabelled.

That capture is a simulation accepted by mainnet. It is not a settlement. Nothing in
this repository signs, broadcasts or holds a key, and the sender address in the
capture is a public mainnet wallet that is not ours.

## What it does not prove

Stage 3 data comes from a local fake, so no on-chain state is involved. Stage 4
proves the build path against mainnet's runtime, not that money moved. Signing stays
outside these components by design: the builder emits an unsigned transaction and the
owner signs it somewhere else.
