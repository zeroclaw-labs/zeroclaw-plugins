# Sample IDL configs

Two minimal Anchor 0.30+ IDLs the `solana-build-tx` plugin looks up by
`program_id`. Drop your real IDLs here, or point the config entry at any path.

| File                                           | Program                      | Program ID                                    | Used for                      |
| ---------------------------------------------- | ---------------------------- | --------------------------------------------- | ----------------------------- |
| [`spl-token-2022.json`](./spl-token-2022.json) | SPL Token-2022               | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` | USDC transfers (demo)         |
| [`tributary.json`](./tributary.json)           | Tributary recurring payments | `TRibg8W8zmPHQqWtyAD1rEBRXEdy13Mu6qX1Sg42tJ`  | `executePayment` via SOP cron |

## Register an IDL

IDLs live under the `idl` subtable of `solana-build-tx`'s config, keyed by the
**full program ID**. The value is either the JSON inlined as a string, or
`@file:<path>` to load from disk (recommended — IDLs are large).

### Via CLI (one key per call)

```bash
# SPL Token-2022
zeroclaw config set \
  plugins.entries.solana-build-tx.config.idl.TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb \
  @file:docs/idl/spl-token-2022.json

# Tributary
zeroclaw config set \
  plugins.entries.solana-build-tx.config.idl.TRibg8W8zmPHQqWtyAD1rEBRXEdy13Mu6qX1Sg42tJ \
  @file:docs/idl/tributary.json
```

### Via TOML (see [`../sample-config.toml`](../sample-config.toml))

```toml
[plugins.entries.solana-build-tx.config.idl]
"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" = "@file:docs/idl/spl-token-2022.json"
"TRibg8W8zmPHQqWtyAD1rEBRXEdy13Mu6qX1Sg42tJ"  = "@file:docs/idl/tributary.json"
```

## What the plugin does with an IDL

1. Looks up the IDL by the `program_id` arg. **Unknown program_id → reject**
   before encoding or simulation (injection vector 5 in the test matrix).
2. Finds the instruction by `instruction_name`. Computes its Anchor
   discriminator as `sha256("global:<snake_case_name>")[0..8]` and checks it
   against the hardcoded blocked-instruction baseline (`approve` family) plus
   the operator's `blocked_instructions_extra`. Match → reject.
3. Borsh-encodes the args per the IDL's arg types. Resolves the `accounts`
   map into account indexes. Emits a `CompiledInstruction`.
4. Assembles a versioned message, runs `simulateTransaction`, and applies the
   simulation-based policy (Layer A balance diff + Layer B token-account
   state diff). See the top-level README §Quickstart for the full flow.

## Replacing the samples

These IDLs are **synthetic** — they have the right shape for the build-tx
plugin to parse and encode, but the SPL Token one omits most instructions and
uses Anchor-style discriminators (the plugin computes them from names per
bean `l59k`). For production, replace either file with the canonical Codama /
Anchor IDL exported from the program build:

```bash
# From an Anchor program workspace:
anchor build            # writes target/idl/<program>.json
cp target/idl/tributary.json docs/idl/tributary.json
```

The Tributary program ID in this sample (`TRibg8W8zmPHQqWtyAD1rEBRXEdy13Mu6qX1Sg42tJ`)
is the real one; verify against the deployment you target before funding.
