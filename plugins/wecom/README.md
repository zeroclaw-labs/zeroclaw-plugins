# WeCom Bot Webhook channel plugin

This plugin implements the same send-only Bot Webhook mode as ZeroClaw's
native `wecom` channel, as a separately installed package.
Text is posted through the host's `wasi:http` implementation, and both HTTP and
WeCom JSON error responses are surfaced to the caller.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info wecom` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install wecom --channel-alias main --egress declared
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry, and `--egress declared` grants the hosts the manifest
declares: `qyapi.weixin.qq.com`. `--egress none` binds with no network reach
instead, and `zeroclaw plugin bind` binds an already installed package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["wecom","channel","<alias>"]`; for `main` it is:

`zpi1_WyJ3ZWNvbSIsImNoYW5uZWwiLCJtYWluIl0`

Set the credentials and settings, then enable the plugin system:

```bash
# Each secret prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJ3ZWNvbSIsImNoYW5uZWwiLCJtYWluIl0.config.webhook_key
zeroclaw config set plugins.enabled true
```

The channel is send-only: route the agent's messages to `plugin.main`. It never
receives, so it needs no sender admission.

```toml
[agents.assistant]
channels = ["plugin.main"]
```

Restart the daemon.

Upgrading from an earlier version: this version reads only its instance's config
entry, never `[channels.wecom.<alias>]` or an older `[[plugins.entries]]` record
named `wecom`. Bind an instance and set the values again under its key, the
credentials through the secret prompt.

## Configuration

Set each non-secret value with
`zeroclaw config set --no-interactive plugins.entries.<instance-key>.config.<key> <value>`;
without `--no-interactive` the command prompts for the value instead. Set a
credential without a value, so the command prompts for it without echo.
Strings are written as is; booleans, integers, and lists as JSON text, for
example `'["a","b"]'`. The schema rejects keys it does not list.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `webhook_key` | string, secret, required |  | The Bot Webhook key. It is bound to one bot conversation, so a message's recipient is ignored. |
| `enabled` | boolean |  | Accepted for compatibility; the plugin does not act on it. |

The plugin reads its config and credentials when the host configures the
instance, so a change takes effect after the instance restarts.

## Validation

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --target wasm32-wasip2 --release
cargo clippy --target wasm32-wasip2 -- -D warnings
```
