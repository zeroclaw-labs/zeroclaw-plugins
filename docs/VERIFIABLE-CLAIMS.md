# Verifiable claims

Every safety claim this suite makes is a property of the shipped bytes, checkable by
a stranger in seconds, with no toolchain, no credentials, no network and no trust in
us. This file is the map from each claim to the check that proves it, the command
that runs it and the primary source that says why it is the right check.

```bash
./demo/verify-all.sh            # every property below holds
./demo/verify-all.sh --report   # the same thing as markdown
python3 demo/prove-teeth.py     # every check below can be made to fail
```

Both also run as stage 5 of `demo/run-demo.sh`, against the bytes that run staged.

## The claims

| Claim | Check | What it reads |
| --- | --- | --- |
| It cannot go looking for a key. | `verify-capabilities.py` | the capability list in both import surfaces of each component |
| It cannot use a key if it is handed one. | `verify-no-ed25519.py` | the absence of SHA-512 constants, with SHA-256 asserted present as a control |
| It cannot ask a node to submit anything. | `verify-rpc-surface.py` | every JSON-RPC method name in the data sections and in the raw file |
| It carries no key material. | `verify-artifact-hygiene.py` | PEM armour, keypair-length base58, 64 character hex, keygen JSON arrays |
| It is the tool the manifest declares. | `verify-artifact-hygiene.py` | the component export section against `manifest.toml` |
| These bytes came from this source. | `verify-provenance.py` | commit, vendored dependency digests, per-plugin source digests, artifact digests |
| Config cannot smuggle anything in. | `verify-config-closure.py` | the schema closed at every object level, declared keys equal to the keys the code reads |
| It fails closed, mostly before the network. | `verify-refusals.py` | every refusal the code constructs against the documented list, plus the ordering |

## Why the capability argument is sound

A WebAssembly component can only do what its imports let it do. That is not our
framing, it is the platform's. [WASI's security page](https://wasi.dev/security)
puts it plainly: "A WASI binary can only do what its host has agreed to let it do. A
component without a filesystem import cannot read files; a component without a
network import cannot open sockets." [WASI's Capabilities.md](
https://github.com/WebAssembly/WASI/blob/main/docs/Capabilities.md) states it in
spec terms, that link-time capabilities in the component model are instance imports.

So the argument runs in the absence direction, which is the only direction that
proves anything. Absent from both surfaces of all three components:

- `wasi:filesystem`, so no keypair file, wallet or `~/.config/solana/id.json` can be
  opened. Not "does not", cannot
- `wasi:sockets`, so every byte of egress goes through the host's outgoing handler,
  where the operator's policy applies
- `wasi:random/random`, leaving only `insecure-seed`, which is what Rust's hash maps
  ask for
- any signing, keystore or wallet interface

## Why custody needs two proofs, not one

The capability list proves the component cannot **seek** a key. It cannot prove key
material never reaches it, because `wasi:cli/environment` and `wasi:cli/stdin` are
imported by Rust's standard library and an operator can put bytes anywhere.

That gap is closed from the other side. Ed25519 is defined in terms of SHA-512, not
merely implemented with it: RFC 8032 section 5.1 specifies SHA-512 for key expansion,
for the per-signature nonce and for the challenge, which is three calls per
signature. Section 5.1.7 uses it again for verification. There is no SHA-512 in these
bytes, so no Ed25519 signature is computable here whatever the component is handed.

The two together are the claim. Each half is narrow on its own:

- it cannot seek a key, because it has no filesystem capability
- it cannot use a key, because it has no way to compute the signature

## What none of this proves

A proof that oversells itself is worth less than a narrow one, so:

- **HTTP egress is imported**, because that is how an RPC read works. Nothing here
  rules out a component handing bytes to a remote signer. What rules out asking a
  node to submit is `verify-rpc-surface.py`, which shows the bytes name no method a
  node would act on, plus the code path and host egress policy.
- **An operator can still hand the component a secret.** The SHA-512 absence is what
  makes that harmless rather than the capability list. `tests/custody.rs` covers the
  config and argument paths.
- **A 32 byte secret key in base58 is 41 to 44 characters. So is an ordinary
  pubkey.** They are the same shape, so no scanner separates them by length. The key
  scan catches a full 64 byte keypair, PEM armour, hex and the keygen JSON array,
  which are the four forms a key actually gets pasted in. It does not catch a bare
  32 byte secret and it cannot.
- **An obfuscated SHA-512 that never materialises the standard constants would evade
  the Ed25519 check.** The positive control is what makes that unlikely rather than
  hoped for: `spl_transfer_build` is asserted to carry all sixteen SHA-256 constants,
  because PDA and associated-token-account derivation need them, so the probe is
  demonstrably able to find hash constants when they exist.
- **The pre-RPC subset rests on a static ordering argument**, not on instrumentation.
  Each refusal is shown to sit on a path that returns before the first HTTP call
  site. `verify-refusals.py` prints the path per guard so the reasoning is
  auditable rather than asserted.
- **The digests reproduce on the same toolchain, not universally.** These were built
  with rustc 1.97.1 while CI pins 1.96.1. The repository's own component
  validator builds from a temporary snapshot path that ends up inside panic strings.
  `verify-provenance.py` records the toolchain alongside the digests so the claim is
  the true one.

## Numbers of record

Every figure below came from one `demo/run-demo.sh` run and can be re-derived by
running it again.

| Component | Bytes | sha256 | Tests |
| --- | --- | --- | --- |
| `nonce_status.wasm` | 332,253 | `ffd4f0ad` | 88 |
| `payment_watch.wasm` | 367,973 | `7f6b8106` | 92 |
| `spl_transfer_build.wasm` | 409,058 | `d57ad6be` | 93 |

273 test executions across three components, 161 distinct, because the shared core's
tests run once per component. 18 end to end scenarios, 3 unsigned transactions built,
9 of the scenarios refuse and 7 of those refuse before any RPC call. 44 refusal
guards in the code, 37 of which return before the component's first HTTP call.
Golden `f51c2e86`. Vendored core `1707bb69`, identical in all three copies. 7 of 7
checks pass, 9 of 9 negative controls provoke their check.

## Sources

- WASI security model: <https://wasi.dev/security>
- WASI capabilities in the component model:
  <https://github.com/WebAssembly/WASI/blob/main/docs/Capabilities.md>
- Ed25519, SHA-512 requirement: RFC 8032 section 5.1
- SHA-256 and SHA-512 constants: FIPS 180-4
- Solana JSON-RPC methods: <https://solana.com/docs/rpc/http>
