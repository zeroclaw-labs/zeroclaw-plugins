# stake-monitor

Read-only T0 stake health reporting with bounded inputs. It never accepts keys, signs,
transfers, or constructs transactions.

The tool accepts bounded `stake` fixtures or parsed `rpc_result` stake-account data. Missing
optional activation fields default conservatively. Run `cargo test --locked` and the
`wasm32-wasip2` release build before installation.
