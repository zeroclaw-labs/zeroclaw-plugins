# solana-sns-resolve

ZeroClaw WIT plugin. Resolves Solana Name Service (.sol) domains to wallet addresses.

## Custody tier: T0 - Read only

No keys. No signing. One HTTPS call to the Bonfida SNS proxy.

## Example

Input: levrone.sol
Output: levrone.sol -> 7xKmNabc...

## Permissions

http_client only. No secrets required.

## Build

```bash
cargo test
cargo build --target wasm32-wasip2 --release
```
