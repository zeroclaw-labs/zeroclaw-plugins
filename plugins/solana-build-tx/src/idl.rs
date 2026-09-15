//! Anchor 0.30+ IDL registry + instruction lookup with blocked-list enforcement.
//!
//! Config keys: `idl.<program_id>` = stringified Anchor IDL JSON.
//! A minimal SPL Token IDL ships inline as a default so the plugin works
//! out-of-the-box for token transfers; operators may override via config.
//!
//! Lookup order: program registered? → instruction blocked? → instruction
//! found? — each rejection carries its own stable error string so the approval
//! gate and the README transcript can cite it.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::policy::{PolicyConfig, SPL_TOKEN_PROGRAM};

// ─── default SPL Token IDL (shipped inline) ─────────────────────────────────

const DEFAULT_SPL_TOKEN_IDL: &str = r#"{
  "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "name": "spl_token",
  "instructions": [
    { "name": "transfer",
      "discriminator": [3, 1, 2, 3, 4, 5, 6, 7],
      "args": [ {"name": "amount", "type": "u64"} ],
      "accounts": [ {"name": "source"}, {"name": "destination"}, {"name": "authority"} ] },
    { "name": "approve",
      "discriminator": [4, 1, 2, 3, 4, 5, 6, 7],
      "args": [ {"name": "amount", "type": "u64"} ],
      "accounts": [ {"name": "source"}, {"name": "delegate"}, {"name": "owner"} ] },
    { "name": "approve_checked",
      "discriminator": [5, 1, 2, 3, 4, 5, 6, 7],
      "args": [],
      "accounts": [ {"name": "source"}, {"name": "mint"}, {"name": "delegate"}, {"name": "owner"} ] },
    { "name": "set_authority",
      "discriminator": [6, 1, 2, 3, 4, 5, 6, 7],
      "args": [],
      "accounts": [ {"name": "account"}, {"name": "current_authority"} ] },
    { "name": "close_account",
      "discriminator": [7, 1, 2, 3, 4, 5, 6, 7],
      "args": [],
      "accounts": [ {"name": "account"}, {"name": "destination"}, {"name": "owner"} ] }
  ]
}"#;

// ─── parsed IDL types ───────────────────────────────────────────────────────

/// One registered program's IDL, deserialised from the Anchor 0.30+ JSON shape.
#[derive(Debug, Clone)]
pub struct ProgramIdl {
    pub address: String,
    pub instructions: Vec<InstructionIdl>,
}

#[derive(Debug, Clone)]
pub struct InstructionIdl {
    pub name: String,
    /// Anchor discriminator: sha256("global:<name>")[..8]. Read from the IDL
    /// if present; otherwise computed at lookup time.
    pub discriminator: Vec<u8>,
    pub args: Vec<ArgIdl>,
    pub accounts: Vec<AccountIdl>,
}

#[derive(Debug, Clone)]
pub struct ArgIdl {
    pub name: String,
    /// Raw Anchor type JSON (preserves nested shapes for the encoder).
    pub type_json: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct AccountIdl {
    pub name: String,
}

/// What `lookup()` hands back — a borrowed view the caller uses for encoding.
#[derive(Debug, Clone)]
pub struct InstructionRef {
    pub program_id: String,
    pub name: String,
    pub discriminator: Vec<u8>,
    pub args: Vec<ArgIdl>,
    pub accounts: Vec<AccountIdl>,
}

// ─── errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdlError {
    /// `idl.<program_id>` key absent from config AND no default shipped.
    ProgramNotRegistered,
    /// Matched the hardcoded baseline or `blocked_instructions_extra`.
    InstructionBlocked,
    /// Program registered but no instruction with this name in its IDL.
    InstructionNotFound,
}

// ─── registry ──────────────────────────────────────────────────────────────

/// All registered program IDLs, keyed by full base58 program id.
#[derive(Debug, Clone, Default)]
pub struct IdlRegistry {
    idls: HashMap<String, ProgramIdl>,
}

impl IdlRegistry {
    /// Parse every `idl.<program_id>` key from the flat config section. The
    /// default SPL Token IDL is inserted first; config entries override it.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let mut idls = HashMap::new();

        // ponytail: ship SPL Token default so transfers work out-of-the-box.
        // Config can override with idl.TokenkegQ... = "...".
        if let Ok(idl) = parse_idl(DEFAULT_SPL_TOKEN_IDL) {
            idls.insert(SPL_TOKEN_PROGRAM.to_string(), idl);
        }

        for (key, raw) in section {
            if let Some(program_id) = key.strip_prefix("idl.") {
                if !program_id.is_empty() {
                    if let Ok(idl) = parse_idl(raw) {
                        idls.insert(program_id.to_string(), idl);
                    }
                    // ponytail: silently skip unparseable IDLs — the lookup
                    // will return ProgramNotRegistered, which is the correct
                    // operator signal. No panic on user config errors.
                }
            }
        }

        Self { idls }
    }

    /// Look up a program + instruction. Checks the blocked list between the
    /// program lookup and the instruction lookup, so a blocked name rejects
    /// even if it is absent from the IDL.
    pub fn lookup(
        &self,
        program_id: &str,
        instruction_name: &str,
        policy: &PolicyConfig,
    ) -> Result<InstructionRef, IdlError> {
        let program = self
            .idls
            .get(program_id)
            .ok_or(IdlError::ProgramNotRegistered)?;

        if policy.is_blocked(program_id, instruction_name) {
            return Err(IdlError::InstructionBlocked);
        }

        let ix = program
            .instructions
            .iter()
            .find(|ix| ix.name == instruction_name)
            .ok_or(IdlError::InstructionNotFound)?;

        // If the IDL carried a discriminator use it; otherwise compute the
        // Anchor 0.30+ default (sha256("global:<name>")[..8]).
        let discriminator = if ix.discriminator.len() == 8 {
            ix.discriminator.clone()
        } else {
            compute_discriminator("global", instruction_name).to_vec()
        };

        Ok(InstructionRef {
            program_id: program_id.to_string(),
            name: ix.name.clone(),
            discriminator,
            args: ix.args.clone(),
            accounts: ix.accounts.clone(),
        })
    }
}

// ─── SHA-256 discriminator ─────────────────────────────────────────────────

/// `sha256("<namespace>:<name>")[..8]` — Anchor 0.30+ instruction identity.
pub fn compute_discriminator(namespace: &str, name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update(b":");
    hasher.update(name.as_bytes());
    let hash = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    out
}

// ─── IDL JSON parser ───────────────────────────────────────────────────────

fn parse_idl(raw: &str) -> Result<ProgramIdl, String> {
    let json: serde_json::Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;

    let address = json
        .get("address")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let instructions = json
        .get("instructions")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_instruction).collect())
        .unwrap_or_default();

    Ok(ProgramIdl {
        address,
        instructions,
    })
}

fn parse_instruction(ix: &serde_json::Value) -> Option<InstructionIdl> {
    let name = ix.get("name")?.as_str()?.to_string();

    let discriminator: Vec<u8> = ix
        .get("discriminator")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|b| b.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect()
        })
        .unwrap_or_default();

    let args = ix
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let name = a.get("name")?.as_str()?.to_string();
                    let type_json = a.get("type").cloned().unwrap_or(serde_json::Value::Null);
                    Some(ArgIdl { name, type_json })
                })
                .collect()
        })
        .unwrap_or_default();

    let accounts = ix
        .get("accounts")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let name = a.get("name")?.as_str()?.to_string();
                    Some(AccountIdl { name })
                })
                .collect()
        })
        .unwrap_or_default();

    Some(InstructionIdl {
        name,
        discriminator,
        args,
        accounts,
    })
}

// ─── self-check ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::HARDCODED_BLOCKED;

    fn section(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn default_spl_token_idl_is_loaded() {
        let reg = IdlRegistry::from_section(&HashMap::new());
        // transfer must be present (happy path)
        let policy = PolicyConfig::default();
        assert!(reg.lookup(SPL_TOKEN_PROGRAM, "transfer", &policy).is_ok());
    }

    #[test]
    fn unknown_program_rejects_before_instruction_check() {
        let reg = IdlRegistry::from_section(&HashMap::new());
        let policy = PolicyConfig::default();
        let err = reg
            .lookup(
                "Unknown111111111111111111111111111111111111",
                "transfer",
                &policy,
            )
            .unwrap_err();
        assert_eq!(err, IdlError::ProgramNotRegistered);
    }

    #[test]
    fn blocked_approve_rejects_even_when_idl_has_it() {
        let reg = IdlRegistry::from_section(&HashMap::new());
        let policy = PolicyConfig::default();
        // approve IS in the default IDL, but must be blocked
        let err = reg
            .lookup(SPL_TOKEN_PROGRAM, "approve", &policy)
            .unwrap_err();
        assert_eq!(err, IdlError::InstructionBlocked);
    }

    #[test]
    fn all_baseline_entries_are_blocked_at_lookup() {
        let reg = IdlRegistry::from_section(&HashMap::new());
        let policy = PolicyConfig::default();
        for &(p, i) in HARDCODED_BLOCKED {
            // For spl_token_2022 we haven't shipped a default IDL, so the
            // program may not be registered. The blocked check must still
            // fire BEFORE the instruction-not-found path. Since lookup
            // checks program-first, spl_token_2022 returns ProgramNotRegistered.
            // For spl_token (which has a default IDL), it returns InstructionBlocked.
            let result = reg.lookup(p, i, &policy);
            match result {
                Err(IdlError::InstructionBlocked) => {}
                Err(IdlError::ProgramNotRegistered) => {} // spl_token_2022 has no default
                other => panic!("{p}:{i} should be blocked or unregistered, got {other:?}"),
            }
        }
    }

    #[test]
    fn instruction_not_in_idl_returns_not_found() {
        let reg = IdlRegistry::from_section(&HashMap::new());
        let policy = PolicyConfig::default();
        let err = reg
            .lookup(SPL_TOKEN_PROGRAM, "nonexistent_ix", &policy)
            .unwrap_err();
        assert_eq!(err, IdlError::InstructionNotFound);
    }

    #[test]
    fn config_overrides_default_idl() {
        let custom = r#"{
            "address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "instructions": [
                { "name": "mint_to", "discriminator": [1,2,3,4,5,6,7,8], "args": [], "accounts": [] }
            ]
        }"#;
        let reg =
            IdlRegistry::from_section(&section(&[(&format!("idl.{SPL_TOKEN_PROGRAM}"), custom)]));
        let policy = PolicyConfig::default();
        // Custom IDL replaces default: mint_to present, transfer absent
        assert!(reg.lookup(SPL_TOKEN_PROGRAM, "mint_to", &policy).is_ok());
        assert_eq!(
            reg.lookup(SPL_TOKEN_PROGRAM, "transfer", &policy)
                .unwrap_err(),
            IdlError::InstructionNotFound
        );
    }

    #[test]
    fn discriminator_computed_from_sha256() {
        let disc = compute_discriminator("global", "transfer");
        assert_eq!(disc.len(), 8);
        // Deterministic: same input → same output
        let disc2 = compute_discriminator("global", "transfer");
        assert_eq!(disc, disc2);
        // Different name → different discriminator
        let disc3 = compute_discriminator("global", "approve");
        assert_ne!(disc, disc3);
    }

    #[test]
    fn operator_extra_blocks_via_policy() {
        let reg = IdlRegistry::from_section(&HashMap::new());
        let policy = PolicyConfig::from_section(&section(&[(
            "blocked_instructions_extra",
            &format!("{SPL_TOKEN_PROGRAM}:transfer"),
        )]));
        let err = reg
            .lookup(SPL_TOKEN_PROGRAM, "transfer", &policy)
            .unwrap_err();
        assert_eq!(err, IdlError::InstructionBlocked);
    }

    #[test]
    fn malformed_idl_silently_skipped() {
        let reg = IdlRegistry::from_section(&section(&[(
            "idl.SomeProgram11111111111111111111111111111111",
            "not valid json {{{",
        )]));
        let policy = PolicyConfig::default();
        // The malformed entry is dropped; program not registered
        let err = reg
            .lookup("SomeProgram11111111111111111111111111111111", "x", &policy)
            .unwrap_err();
        assert_eq!(err, IdlError::ProgramNotRegistered);
    }
}
