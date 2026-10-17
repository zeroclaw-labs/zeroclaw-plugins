# wechat — ZeroClaw channel plugin

A [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) **channel** plugin that
connects your agent to a personal WeChat account through the **iLink Bot** API
(`ilinkai.weixin.qq.com`). It long-polls `getupdates` for incoming messages and
sends the agent's replies with `sendmessage` — all from a sandboxed
`wasm32-wasip2` WIT component, with no native build.

## Session / login

The iLink Bot API is authorized with a `bot_token` that is obtained by scanning
a **QR code** with the WeChat phone app. That login is interactive (render a QR
to a terminal, then long-poll for the scan), which cannot run inside the wasm
sandbox. So this plugin does **not** perform the QR login itself — you establish
the session once with the native `zeroclaw` `wechat` channel (which renders the
QR and persists the token to `~/.zeroclaw/wechat/account.json`), then set that
`bot_token` as this instance's secret.

The schema requires `bot_token`, so an instance without one does not
activate. If the token later expires (iLink `errcode -14`), the plugin drops
it and goes inert: `poll` returns nothing and `send` reports the missing
session. Run the native QR login again, set the new token with the secret
prompt, and restart the instance; the plugin reads the token when the host
configures it.

## Host requirement

The plugin binds the host contract first released in ZeroClaw v0.8.6: typed
config through `config.get`, and its credentials through `secrets.get`. Released
versions up to ZeroClaw v0.8.5 do not load it. The host also needs the Cranelift
backend, which compiles `.wasm` components (`--features plugins-wasm-cranelift`
in a source build).

`zeroclaw plugin install` instantiates the component before it installs
anything, and `zeroclaw plugin info wechat` repeats that check, so an
incompatible host refuses the package with the reason instead of failing at
startup.

## Install and bind an instance

The plugin runs only as a named channel instance, `plugin.<alias>`. For an
instance named `main`:

```bash
zeroclaw plugin install wechat --channel-alias main --egress declared
```

`--channel-alias` writes the `[channels.plugin.main]` binding and creates the
instance's config entry, and `--egress declared` grants the hosts the manifest
declares: `ilinkai.weixin.qq.com`. `--egress none` binds with no network reach
instead, and `zeroclaw plugin bind` binds an already installed package.

The instance key is `zpi1_` followed by the unpadded base64url of the JSON
array `["wechat","channel","<alias>"]`; for `main` it is:

`zpi1_WyJ3ZWNoYXQiLCJjaGFubmVsIiwibWFpbiJd`

Set the credentials and settings, then enable the plugin system:

```bash
# Each secret prompts without echo and is stored encrypted.
zeroclaw config set plugins.entries.zpi1_WyJ3ZWNoYXQiLCJjaGFubmVsIiwibWFpbiJd.config.bot_token
zeroclaw config set plugins.enabled true
```

Route the instance to an agent and admit the senders it may answer:

```toml
[agents.assistant]
channels = ["plugin.main"]

[peer_groups.wechat_main]
channel = "plugin.main"
external_peers = ["<sender>"]
```

Restart the daemon. Do not also run the built-in channel with the same
credentials, or both answer.

Upgrading from an earlier version: this version reads only its instance's config
entry, never `[channels.wechat.<alias>]` or an older `[[plugins.entries]]`
record named `wechat`. Bind an instance and set the values again under its key,
the credentials through the secret prompt.

## Configuration

Set each non-secret value with
`zeroclaw config set --no-interactive plugins.entries.<instance-key>.config.<key> <value>`;
without `--no-interactive` the command prompts for the value instead. Set a
credential without a value, so the command prompts for it without echo.
Strings are written as is; booleans, integers, and lists as JSON text, for
example `'["a","b"]'`. The schema rejects keys it does not list.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bot_token` | string, secret, required |  | The iLink session token from a one-time native QR login (see [Session / login](#session--login)). |
| `api_base_url` | URL | `https://ilinkai.weixin.qq.com` | iLink API origin. Override for a test mock, and grant that host. |
| `cdn_base_url` | URL | `https://novac2c.cdn.weixin.qq.com/c2c` | iLink CDN origin. Accepted for compatibility; media transfer is not implemented. |
| `state_dir` | string |  | Accepted for compatibility; the plugin does not act on it. |
| `enabled` | boolean |  | Accepted for compatibility; the plugin does not act on it. |
| `excluded_tools` | list of strings |  | Accepted for compatibility; the plugin does not act on it. |

The plugin reads its config and credentials when the host configures the
instance, so a change takes effect after the instance restarts.

## Permissions

- `http_client` — outbound calls to the iLink Bot API (TLS is performed
  host-side).
- `config_read` — read the typed config through `config.get`; the credentials
  arrive only through `secrets.get`.

## What's covered

`src/wechat.rs` holds the pure iLink logic (message → inbound mapping,
`getupdates` / `sendmessage` / `getconfig` body building, error/session-expiry
classification, cursor + context-token handling, a Markdown→plain-text pass, and
the `X-WECHAT-UIN` Base64 helper) with host `cargo test` coverage in `tests/`.
`src/lib.rs` is the thin component shim that does the HTTP via the blocking
[`waki`](https://crates.io/crates/waki) `wasi:http` client, sending the iLink
auth headers (`Authorization: Bearer …`, `AuthorizationType: ilink_bot_token`,
`X-WECHAT-UIN`).

Inbound text and voice-transcription messages are delivered today; the poll caps
the server hold (`longpolling_timeout_ms: 0`) so it never stalls `send`. WeChat
conversations are 1:1, so a reply's recipient is the sender's `from_user_id`, and
the per-sender `context_token` harvested on poll is reused to thread the reply.
Media (images, files, voice notes) and the `/bind` pairing flow are handled by
the native channel and are future work here.

## Build

```bash
rustup target add wasm32-wasip2
cargo test                                   # pure core, on the host
cargo build --release --target wasm32-wasip2 # the component
```
