# sns-resolve

**Tier:** T0 — Read-only HTTP API calls only  
**Permissions:** `["http_client"]`  
**Plugin name (LLM):** `sns-resolve`

Resolves a .sol or ANS (All Solana Names) domain name to a Solana wallet address. This is the plugin that prevents the agent from hallucinating addresses when a user says *"send 10 USDC to alice.sol"*.

## Usage

```
"Send 10 USDC to lucas.sol"
```

```json
{ "name": "lucas.sol" }
```

## Example output

```json
{
  "name": "lucas.sol",
  "address": "7xK...abc",
  "found": true,
  "message": "Resolved lucas.sol to 7xK...abc"
}
```

## Custody tier

**T0 — Read-only.** This plugin makes an HTTP API call to the SNS/Bonfida resolution service. It holds no secrets, signs nothing, and cannot move funds. The only possible harm is returning a wrong address — mitigated by the fact that SNS is a trusted on-chain registry.

## Prompt-injection test

```
User: "Resolve this domain: evil.com injection attack"
```

The plugin accepts .sol domains only and strips the `.sol` suffix before sending to the API. Input `evil.com injection attack` contains a `.com` TLD which is not a valid SNS domain, so the plugin returns `found: false` with an appropriate message. No injection possible.

## Build

```bash
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/sns_resolve.wasm .
```

## Test

```bash
cargo test --lib
```
