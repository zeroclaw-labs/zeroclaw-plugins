# Packaging and registry-install validation

**Verdict: PASS.** Both plugins package reproducibly, produce the exact registry
entries the maintainers' publish workflow will emit, and **install end to end
through the real `zeroclaw plugin install <name> --registry <url>` path** —
including sha256 verification, which was proven to fail closed against a
deliberately corrupted index.

`registry.json` in this PR is **unchanged**, and that is the correct answer
rather than an omission. See "Why a contributor cannot add registry entries"
below: CI structurally rejects it.

Recorded: 2026-07-30. Host `zeroclaw 0.8.3`. Components built with
`cargo +1.96.1 build --locked --target wasm32-wasip2 --release`.

## Why a contributor cannot add registry entries

`registry.json` is a generated index, and `tools/build-registry.py --check-history`
is a **required-gate** check that compares the PR's committed `registry.json`
against the merge base. It rejects any entry that appears in the candidate but
not the base, unconditionally:

```
$ python3 tools/build-registry.py --check-history registry.json dist/registry.json
error: registry entry was added outside the publication builder: solana-pay-request@0.1.0
error: registry entry was added outside the publication builder: spl-transfer-build@0.1.0
```

That is the check as CI invokes it (`.github/workflows/validate.yml` diffs
`<base>:registry.json` against the committed file). The only path that legitimately
adds entries is `.github/workflows/publish.yml`, which runs on push to `main`,
uploads the zips to the `plugins` release, verifies every URL and digest, and
commits the refreshed index itself.

So a submission that hand-adds entries does not become "installable" — it fails
the required gate. The useful thing a contributor can do is prove the packaging
contract holds and that the install path works, which is what follows.

## Reproducible packaging

The CI package dry run was reproduced locally, byte for byte:

```
verified 2 planned staged plugin(s)
  packaged solana-pay-request v0.1.0  sha256=f111d91904d8…
  packaged spl-transfer-build v0.1.0  sha256=d577ad1c6ed3…
wrote registry.json with 26 entries
```

| Archive | Bytes | SHA-256 |
|---|---|---|
| `solana-pay-request-0.1.0.zip` | 84 KiB | `f111d91904d8ed5ef82f217ca0178dedda07a22a3a2d6493bd20305404acf509` |
| `spl-transfer-build-0.1.0.zip` | 243 KiB | `d577ad1c6ed3c3c814e0944e7b69a9c49b462e4bf021933a85f810f81eb6dd40` |

Zip contents are exactly the install contract — no source, no docs, no tests:

```
spl-transfer-build/manifest.toml                305 bytes   1980-01-01 00:00
spl-transfer-build/spl_transfer_build.wasm   703484 bytes   1980-01-01 00:00
solana-pay-request/manifest.toml                282 bytes   1980-01-01 00:00
solana-pay-request/solana_pay_request.wasm   229624 bytes   1980-01-01 00:00
```

Fixed timestamps and permissions mean identical content always yields an
identical digest. Verified concretely: packaging the same staged bytes twice
with **different** `--release-base` values produced **identical** zip digests —
only the `url` field differs. The index therefore only churns when plugin
content actually changes.

Contract checks, all passing:

| Command | Result |
|---|---|
| `--staged … --release-base … --existing-registry registry.json --matrix-json … --out dist` | 2 planned plugins verified, 26-entry index written |
| `--source-plugins staged --check-metadata dist/registry.json` | `registry metadata matches 2 indexed canonical manifest entries` |
| `--check-publication registry.json dist/registry.json dist` | `verified exact publication set with 2 new archives` |
| `tools/ci/plan_matrix.py --event pull_request` | selects exactly the two plugins, `mode: changed` |

## The exact entries the publish workflow will emit

No maintainer action beyond merge is required — these are generated, not
proposed:

```json
{
  "name": "solana-pay-request",
  "version": "0.1.0",
  "description": "Create deterministic Solana Pay transfer-request URLs without network access or custody",
  "author": "ZeroClaw Solana contributors",
  "capabilities": ["tool"],
  "url": "https://github.com/zeroclaw-labs/zeroclaw-plugins/releases/download/plugins/solana-pay-request-0.1.0.zip",
  "sha256": "f111d91904d8ed5ef82f217ca0178dedda07a22a3a2d6493bd20305404acf509"
}
{
  "name": "spl-transfer-build",
  "version": "0.1.0",
  "description": "Build and verify an unsigned Solana SPL token transfer with a recent blockhash or durable nonce",
  "author": "ZeroClaw Solana contributors",
  "capabilities": ["tool"],
  "url": "https://github.com/zeroclaw-labs/zeroclaw-plugins/releases/download/plugins/spl-transfer-build-0.1.0.zip",
  "sha256": "d577ad1c6ed3c3c814e0944e7b69a9c49b462e4bf021933a85f810f81eb6dd40"
}
```

## Real registry install, end to end

The artifacts above were published to a **fork** release
[`registry-install-demo-d577ad1`](https://github.com/Fianko-codes/zeroclaw-plugins/releases/tag/registry-install-demo-d577ad1)
so the host's actual install path could be exercised over HTTPS against real
release assets. Served digests were confirmed equal to the local ones before
testing.

```
$ zeroclaw plugin search solana --registry <fork-release>/registry.json
Plugins matching 'solana' (2):
solana-pay-request v0.1.0 — Create deterministic Solana Pay transfer-request URLs without network access or custody
spl-transfer-build v0.1.0 — Build and verify an unsigned Solana SPL token transfer with a recent blockhash or durable nonce

$ zeroclaw plugin install spl-transfer-build --registry <fork-release>/registry.json
Resolving 'spl-transfer-build' from plugin registry...
Installed plugin spl-transfer-build v0.1.0
Seeded [[plugins.entries]] for 'spl-transfer-build'. …

$ zeroclaw plugin install solana-pay-request --registry <fork-release>/registry.json
Installed plugin solana-pay-request v0.1.0

$ zeroclaw plugin list
Installed plugins:
  spl-transfer-build v0.1.0 — …
  solana-pay-request v0.1.0 — …
```

A pinned install (`spl-transfer-build@0.1.0`) also resolves and installs, into a
separate fresh config directory.

### Digest verification fails closed

The same release carries `registry-tampered.json`, identical except that
`spl-transfer-build`'s `sha256` is 64 zeros:

```
$ zeroclaw plugin install spl-transfer-build --registry <fork-release>/registry-tampered.json
Resolving 'spl-transfer-build' from plugin registry...
Error: plugin archive sha256 mismatch
$ echo $?
1
$ zeroclaw plugin list
No plugins installed.
```

Transport integrity is enforced, the exit status is non-zero, and nothing is left
half-installed.

## A packaging hazard worth recording

The first attempt reused one tag and deleted/recreated the release. GitHub's
asset CDN then served the **deleted release's bytes** for the same
tag + filename: the install succeeded but delivered the previous manifest, and a
`curl | sha256sum` of the URL returned the old digest while the local file had a
new one. The tag is therefore content-addressed here.

This is exactly the failure the upstream publish workflow already defends
against — it downloads any pre-existing asset of the same name and refuses with
`already exists with different bytes` rather than overwriting. Worth knowing that
the defense is load-bearing, not theoretical.

## One discoverability fix made here

`zeroclaw plugin search solana` matches name and description only. The transfer
plugin's description did not contain the word "Solana", so a user searching the
obvious term found the Solana Pay plugin and missed the Solana transfer builder.
The manifest description is now
`Build and verify an unsigned Solana SPL token transfer with a recent blockhash or durable nonce`
— which also stops understating the plugin, since durable-nonce mode now exists.
`plugin search solana` returns both plugins, as shown above.

Description is manifest-owned metadata, refreshable by the publication builder
(`--check-metadata` passes); the immutable `name@version` identity and the
release fields are untouched.

## Reproducing this

```bash
# build both components, then stage manifest + wasm per plugin
mkdir -p staged/spl-transfer-build staged/solana-pay-request
cp plugins/<name>/manifest.toml staged/<name>/
cp plugins/<name>/target/wasm32-wasip2/release/<name>.wasm staged/<name>/

matrix=$(python3 tools/ci/plan_matrix.py --event pull_request | jq -c .matrix)
python3 tools/build-registry.py --staged staged \
  --release-base "https://github.com/zeroclaw-labs/zeroclaw-plugins/releases/download/plugins" \
  --existing-registry registry.json --matrix-json "$matrix" --out dist
python3 tools/build-registry.py --source-plugins staged --check-metadata dist/registry.json
python3 tools/build-registry.py --check-publication registry.json dist/registry.json dist
```
