# redact-text

The canonical ZeroClaw **WIT component** tool plugin (adopted from
[zeroclaw-reference-plugin](https://github.com/singlerider/zeroclaw-reference-plugin),
renamed for what it does). It implements the `tool-plugin` world from `wit/v0`
and compiles to a `wasm32-wasip2` component. Copy it as the starting point for
a real tool plugin.

## What it does

A `redact` tool. It scrubs secrets and PII out of text before that text reaches
a log, a channel, or a model: email addresses, bearer/API tokens (`sk-`, `ghp_`,
`AKIA`, `xoxb-`, …), and any literal patterns the operator configures.

The redaction policy comes entirely from the plugin's own config section, which
makes this the reference for the four things every config-aware plugin must do:

1. **Declare a `config_schema`.** `manifest.toml` carries a closed Draft 2020-12
   object naming every key this plugin reads. It is a biconditional with the
   `config_read` permission: the host rejects a manifest that has one without
   the other, so a package that skips this is no longer discovered or installed.
2. **Own a config section.** The operator configures the plugin under its
   full-instance key (`zeroclaw plugin info redact-text` prints it); the host
   resolves that one section and validates it against the schema.
3. **Deserialize typed JSON.** `execute` reads the injected `__config` object
   out of its arguments in one `serde` step. The host has already turned the
   operator's stored strings into real booleans and arrays according to the
   schema, so the guest does no string parsing.
4. **Stay jailed.** The host only injects values when the manifest requests
   `config_read` *and* the grant is in effect. Without the grant the plugin
   receives `{}` and falls back to defaults. A plugin can never read the global
   config or another plugin's section.

## Config keys

Every key is optional, so the plugin runs on defaults with no config at all.

| Key | Schema type | Default | Meaning |
|---|---|---|---|
| `replacement` | `string` (`minLength` 1) | `[REDACTED]` | Text substituted for each redacted span. |
| `redact_emails` | `boolean` | `true` | Mask email-shaped substrings. |
| `patterns` | `array` of `string` (`minLength` 1) | (empty) | Additional literal substrings to mask. |

Operator storage is still a string map, and the schema tells the host how to
read each stored string. Set a boolean and an array like this:

```bash
key=$(zeroclaw plugin info redact-text)   # prints the zpi1_... instance key
zeroclaw config set "plugins.entries.$key.config.redact_emails" 'false'
zeroclaw config set "plugins.entries.$key.config.patterns" '["project-zeus","internal-codename"]'
```

`patterns` was a comma-separated string before 0.3.0. It is a JSON array now,
and the host rejects the old encoding rather than silently misreading it.

## Layout (the reference format)

```
src/redact.rs   # pure logic, no wasm deps — host-testable with `cargo test`
src/lib.rs      # thin #[cfg(target_family = "wasm")] component shim
tests/          # host-run integration tests over the pure core
manifest.toml   # name, version, wasm_path, capabilities, permissions, config_schema
```

The version appears in three files that must agree: `manifest.toml` (the
canonical release identity), `Cargo.toml` (CI fails the package if it differs),
and `Cargo.lock` (CI builds with `--locked`). `plugin-info` reports
`CARGO_PKG_VERSION`, so `Cargo.toml` is what the running plugin announces.

## Build and test

```bash
cargo test                                        # host tests, no wasm needed
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release      # the component
cp target/wasm32-wasip2/release/redact_text.wasm redact_text.wasm
```

## Install

```bash
zeroclaw plugin install redact-text
```

or copy this directory (the `.wasm` next to its `manifest.toml`) into your
configured plugins dir, then enable plugins and (optionally) configure it:

```toml
[plugins]
enabled = true
```

Run the agent with a build that includes a compiler backend, e.g.
`--features plugins-wasm,plugins-wasm-cranelift`. For runtime-only hosts
(`--features plugins-wasm`), precompile with a matching wasmtime:
`wasmtime compile --target <triple> redact_text.wasm -o redact_text.cwasm` and
point `wasm_path` at the `.cwasm`.
