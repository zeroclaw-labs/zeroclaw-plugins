# RPC fixtures

Raw JSON-RPC responses captured from mainnet on 2026-07-19, used by the host
tests so `cargo test` never touches the network.

| file | mint | method | endpoint |
|---|---|---|---|
| `usdc_account.json` | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` | getAccountInfo | api.mainnet-beta.solana.com |
| `usdc_largest.json` | ″ | getTokenLargestAccounts | solana.lava.build |
| `pyusd_account.json` | `2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo` | getAccountInfo | api.mainnet-beta.solana.com |
| `pyusd_largest.json` | ″ | getTokenLargestAccounts | solana-rpc.publicnode.com |
| `bern_account.json` | `CKfatsPMUf8SkiURsDXs7eK6GWb4Jsd6UDbs7twMCWxo` | getAccountInfo | api.mainnet-beta.solana.com |
| `bern_largest.json` | ″ | getTokenLargestAccounts | solana-rpc.publicnode.com |

Why these three:

- **USDC** — legacy spl-token mint (82-byte layout, no TLV region). Mint and
  freeze authorities active; top-10 concentration ~36%.
- **PYUSD** — Token-2022 with a dense TLV region: MintCloseAuthority,
  PermanentDelegate, TransferFeeConfig (0 bps), ConfidentialTransfer entries,
  TransferHook, MetadataPointer, TokenMetadata. Permanent delegate makes it
  the red-verdict fixture.
- **BERN** — Token-2022 with a live transfer fee (269 bps) and no
  authorities: the amber-verdict fixture.
