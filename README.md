# ZeroClaw Plugin Registry

The official catalog of [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw)
WASM plugins — **self-contained WIT components** the agent can fetch and install
on demand. This is what `zeroclaw plugin search` and
`zeroclaw plugin install <name>` read by default.

```bash
zeroclaw plugin search redact
zeroclaw plugin install redact-text
zeroclaw plugin install redact-text@0.1.0    # pin a version
```

## What's in this repo

```
plugins/<name>/        # published plugins — one wit-bindgen component per directory
  Cargo.toml           # cdylib + rlib, wit-bindgen, standalone [workspace]
  src/lib.rs           # thin #[cfg(target_family = "wasm")] component shim
  src/<core>.rs        # pure logic, no wasm deps — host-testable
  tests/               # host-run tests over the pure core (`cargo test`)
  manifest.toml        # name, version, wasm_path, capabilities, permissions
  README.md
wit/v0/                # vendored ZeroClaw plugin WIT contract, as ZeroClaw v0.8.6 ships it (pinned by wit/UPSTREAM_REF)
wit/next/              # an earlier pre-release snapshot, kept for source-only plugins (pinned by wit/NEXT_REF)
wit/unstable/          # the pre-v0.8.6 draft tree; plugins built against it do not install on v0.8.6
registry.json          # GENERATED index — published by CI, do not hand-edit
registry-retirements.json  # reviewed list of versions withdrawn from the index
tools/build-registry.py
.github/workflows/publish.yml
```

Plugins are **WebAssembly components** built for `wasm32-wasip2` against the WIT
world `tool-plugin` (`wit/v0/`). They run sandboxed and deny-by-default: the
host grants only the capabilities a plugin's `manifest.toml` declares.

`wit/v0/` is vendored **unmodified** from
[zeroclaw `wit/v0`](https://github.com/zeroclaw-labs/zeroclaw/tree/master/wit/v0)
— it is the contract the host actually implements. Network access is
deny-by-default: a plugin reaches only the hosts an operator grants its
instance, for example with `--egress declared` when binding it.

`wit/v0/` matches the contract ZeroClaw v0.8.6 ships: typed config through
`config.get`, schema-designated secrets through `secrets.get`, the host
`websocket` resource, sockets and durable `state`. Channel packages built
against an earlier `wit/v0` or `wit/unstable/`, and redact-text before 0.3.0,
do not install on v0.8.6. Their published versions are withdrawn through
[`registry-retirements.json`](./registry-retirements.json), and each such
channel package returns to the registry at a new version once it is ported.

`wit/next/` is an earlier pre-release snapshot of the same contract, pinned by
`wit/NEXT_REF`. It remains only for source plugins that have not moved to
`wit/v0/` yet, and CI still withholds it from plugins headed for the registry
(see [Host-gated source plugins](#host-gated-source-plugins)). CI checks
`wit/v0/` and `wit/next/` byte for byte against their pins.

## How install works

- [`registry.json`](./registry.json) is a single index, fetched from
  `https://raw.githubusercontent.com/zeroclaw-labs/zeroclaw-plugins/main/registry.json`.
- Each entry's `url` points to a zipped plugin directory published as a
  **GitHub Release asset** — binaries are never committed to git, only the small
  text index.
- On install the CLI downloads the zip, **verifies the `sha256`** (transport
  integrity), then the host enforces the configured **Ed25519 `signature_mode`**
  (authenticity).

### Index format

```json
{
  "plugins": [
    {
      "name": "redact-text",
      "version": "0.1.0",
      "description": "Redact secrets and PII from text: emails, bearer/API tokens, and configured patterns",
      "author": "ZeroClaw Labs",
      "capabilities": ["tool"],
      "url": "https://github.com/zeroclaw-labs/zeroclaw-plugins/releases/download/plugins/redact-text-0.1.0.zip",
      "sha256": "<hex digest of the zip>"
    }
  ]
}
```

Channel entries also project optional `provides` and `sender_match` values
directly from their `manifest.toml`. The registry never carries a second,
hand-maintained channel mapping.

`registry.json` is **generated** — the [publish workflow](./.github/workflows/publish.yml)
builds every `plugins/*`, packages the zips, uploads them to the `plugins`
release, and commits a refreshed index. The checked-in copy is a seed; the
`sha256`/`url` become live once the publish workflow uploads the release assets.

Published `<name>@<version>` identities are immutable. The workflow verifies an
existing asset's digest and reuses its registry entry, but never uploads over
it. Any source, manifest, compiler, or WIT change that changes the package bytes
requires a new manifest version; new versions are appended so pinned installs
continue resolving to their original artifact.

A version that no supported host can run can be withdrawn from the index by
listing it, with its archive digest and a reason, in
[`registry-retirements.json`](./registry-retirements.json). The next
publication drops it from `registry.json`; its release asset stays, and the
version can never be published again: validation keeps the ledger
append-only. See
[Retiring a published version](./docs/ci.md#retiring-a-published-version).

## Add a plugin

Start with the **plugin authoring guide series** in the ZeroClaw book
([`docs/book/src/plugins/`](https://github.com/zeroclaw-labs/zeroclaw/tree/master/docs/book/src/plugins),
added in [zeroclaw#8621](https://github.com/zeroclaw-labs/zeroclaw/pull/8621)) —
worked guides for tool, channel, and memory plugins plus distribution and
signing, with every claim derived from `wit/v0/` and the host source.

Then use [`plugins/redact-text`](./plugins/redact-text) as the template — it is
the canonical reference plugin (adopted from
[zeroclaw-reference-plugin](https://github.com/singlerider/zeroclaw-reference-plugin))
and its layout is the required format:

1. **Pure core, thin shim.** Keep the actual logic in a plain Rust module with
   no wasm dependency; implement the `tool-plugin` world in a
   `#[cfg(target_family = "wasm")]` module that calls into it. Crate type
   `["cdylib", "rlib"]`.
2. **Host-run tests.** `tests/` must exercise the core with a plain
   `cargo test` — no wasm toolchain needed to validate behavior.
3. **Structured logging.** Emit through the `logging` import (`log-record`), not
   stdout.
4. **Manifest.** `manifest.toml` with `name` (kebab-case, says what it does),
   `version`, `wasm_path`, `capabilities`, and only permissions the host
   actually supports (`http_client`, `file_read`, `file_write`, `config_read`,
   `memory_read`, `memory_write`, `socket_client`, `websocket_client`).
   `state_read` and `state_write` are host-gated: released hosts reject them,
   so CI accepts them only in a `registry = false` plugin.
5. Build it:
   ```bash
   rustup target add wasm32-wasip2
   (cd plugins/<name> && cargo test --locked && cargo build --locked --target wasm32-wasip2 --release)
   ```
6. Run the repository validation:
   ```bash
   python3 -m unittest discover -s tools/tests -p 'test_*.py'
   python3 tools/build-registry.py --retirements registry-retirements.json \
     --source-plugins plugins --check-metadata registry.json
   ```
7. Open a PR. PR validation host-tests and builds every component against the
   vendored WIT, checks registry metadata drift, and rejects changed bytes at an
   already-published name/version. On merge, the publish workflow packages only
   new immutable versions and indexes them.

### Host-gated source plugins

Some channel migrations need a host capability or protocol port that is not
ready for the install registry yet. Keep that source in `plugins/<name>/`, but
set `registry = false` in `manifest.toml`:

```toml
registry = false
```

The publish workflow skips those plugins entirely: no build, no zip, and no
`registry.json` entry. Remove the guard only when stock hosts can run the
plugin and the protocol parity tests are in place.

A plugin that needs an interface only an unreleased host provides binds
`wit/next/` instead of `wit/v0/`, and it may request the host-gated
`state_read` and `state_write` permissions. Both require `registry = false`:
CI rejects a host-gated permission in a plugin headed for the registry, and
builds such a plugin without `wit/next/`.

## Run your own registry

```bash
zeroclaw plugin install <name> --registry https://my-host/registry.json
export ZEROCLAW_PLUGIN_REGISTRY_URL=https://my-host/registry.json
```
