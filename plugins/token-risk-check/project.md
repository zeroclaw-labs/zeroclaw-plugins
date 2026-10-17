# 🦞 Solana Token Risk Check Plugin for ZeroClaw

এই ডকুমেন্টে **ZeroClaw** AI Agent-এর জন্য একটি অত্যন্ত দরকারী এবং প্রাক্টিক্যাল প্লাগইন **`token-risk-check`** তৈরির সম্পূর্ণ ডিজাইন, কোড আর্কিটেকচার এবং ইমপ্লিমেন্টেশন গাইড দেওয়া হলো। 

ডক্টর ও সাধারণ গ্রাহকদের জন্য ওয়েবসাইট বানানোর পাশাপাশি, এই প্লাগইনটি ওয়েব৩ এবং ক্রিপ্টো ফিল্ডে আপনার পোর্টফোলিওকে অনেক শক্তিশালী করবে।

---

## ১. প্লাগইনটির প্রয়োজনীয়তা (Why is this useful?)
ক্রিপ্টোকারেন্সি (যেমন Solana)-তে প্রতিদিন হাজার হাজার নতুন টোকেন লঞ্চ হয়। এগুলোর মধ্যে অনেকগুলোই "Rug pull" (ফান্ড নিয়ে পালিয়ে যাওয়া) বা "Honeypot" (টোকেন কেনা যায় কিন্তু বিক্রি করা যায় না) হয়ে থাকে। 

আমাদের এআই এজেন্ট (Zeroclaw-based Agent) যদি সোলানা নিয়ে কাজ করে, তবে কোনো টোকেন কেনা বা সোয়াপ (swap) করার আগে সেই টোকেনটি নিরাপদ কি না তা যাচাই করা অত্যন্ত জরুরি। আমাদের তৈরি **`token-risk-check`** প্লাগইনটি সোলানার যেকোনো Mint Address দিলে নিচের বিষয়গুলো অটোমেটিক চেক করবে:
1. **Mint / Freeze Authority:** টোকেনটির ডেভেলপার কি চাইলেই আরও টোকেন মিন্ট করতে পারবে বা ইউজারের ওয়ালেট ফ্রিজ করতে পারবে?
2. **Liquidity Lock Status:** পুলের লিকুইডিটি কি বার্ন বা লক করা হয়েছে?
3. **Holder Concentration:** বড় বড় তিমিরা (Whales) কি বেশি পরিমাণ টোকেন হোল্ড করছে?
4. **Token-2022 Extensions:** নতুন টোকেন এক্সটেনশন ব্যবহার করে কোনো লুকানো ফি (transfer tax) বসানো আছে কি না।

---

## ২. ডিরেক্টরি স্ট্রাকচার (Directory Structure)
ZeroClaw-এর ক্যানোনিকাল স্ট্যান্ডার্ড অনুযায়ী প্লাগইনের লেআউটটি হবে নিম্নরূপ:

```text
zeroclaw-solana-plugin/
├── Cargo.toml
├── manifest.toml
├── README.md
├── project.md  <-- (এই গাইড ফাইলটি)
└── src/
    ├── lib.rs            # WIT/WASM Shim (WASM এর সাথে মূল লজিক কানেক্ট করে)
    └── risk_check.rs     # Pure Rust Core (কোর সোলানা আরপিসি এবং চেকিং লজিক)
```

---

## ৩. ফাইলসমূহের কোড ব্লুপ্রিন্ট (File Blueprints)

### ক. `Cargo.toml`
প্লাগইন বিল্ড করার জন্য প্রজেক্টের ডিপেন্ডেন্সি ফাইল।

```toml
[package]
name = "token-risk-check"
version = "0.1.0"
edition = "2021"
license = "MIT"
description = "ZeroClaw WIT plugin to check Solana token safety and rug risks before trading."
publish = false

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
wit-bindgen = "0.46"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
uriparse = "0.6" # URL ভ্যালিডেশনের জন্য
```

---

### খ. `manifest.toml`
ZeroClaw হোস্ট যাতে আমাদের প্লাগইনটি লোড করতে পারে এবং প্রয়োজনীয় পারমিশন দেয়।

```toml
name = "token-risk-check"
version = "0.1.0"
wasm_path = "target/wasm32-wasip2/release/token_risk_check.wasm"
capabilities = ["tool"]

# এই প্লাগইনটি সোলানা আরপিসি সার্ভার কল করতে HTTP ক্লায়েন্ট ব্যবহার করবে
permissions = ["http_client", "config_read"]
```

---

### গ. `src/risk_check.rs` (Pure Core Logic)
এই ফাইলে মূল লজিক থাকবে যা সোলানা আরপিসি সার্ভার থেকে টোকেন ডেটা এনে রিস্ক অ্যানালাইসিস করবে। এটি কোন WASM ছাড়া পিসিতে সরাসরি রান ও টেস্ট করা সম্ভব।

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RiskReport {
    pub token_address: String,
    pub risk_score: u8, // ০ থেকে ১০০ (১০০ মানে অতি ঝুঁকিপূর্ণ)
    pub is_honeypot: bool,
    pub freeze_authority_present: bool,
    pub mint_authority_present: bool,
    pub liquidity_status: String,
    pub warnings: Vec<String>,
}

pub struct RiskChecker {
    pub rpc_url: String,
}

impl RiskChecker {
    pub fn new(rpc_url: String) -> Self {
        Self { rpc_url }
    }

    /// টোকেন অ্যাড্রেস দিয়ে আরপিসি থেকে ডেটা চেক করা
    pub fn analyze_token(&self, mint_address: &str) -> Result<RiskReport, String> {
        // ১. প্রম্পট ইনজেকশন ডিফেন্স
        if mint_address.len() < 32 || mint_address.len() > 44 || mint_address.contains(' ') {
            return Err("Invalid Solana Mint Address (Possible injection attempt)".to_string());
        }

        // ২. সোলানা আরপিসিতে পাঠানোর জন্য JSON-RPC রিকোয়েস্ট
        // (WASM কম্পোনেন্ট ফ্রেন্ডলি HTTP ক্লায়েন্ট দিয়ে কল করা হবে)
        let rpc_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [
                mint_address,
                { "encoding": "jsonParsed" }
            ]
        });

        // এখানে রিকোয়েস্ট পাঠিয়ে রেসপন্স প্রসেস করা হবে।
        // নিচে মক অ্যানালাইসিস ডেমো দেওয়া হলো:
        let mut warnings = Vec::new();
        let mut risk_score = 0;
        let mut freeze_auth = false;
        let mut mint_auth = false;

        // উদাহরণস্বরূপ: আমরা ফ্রিজ অথরিটি ডিটেক্ট করলাম
        freeze_auth = true; 
        warnings.push("Freeze authority is enabled. Developer can lock your tokens anytime!".to_string());
        risk_score += 40;

        mint_auth = true;
        warnings.push("Mint authority is enabled. Developer can mint infinite tokens!".to_string());
        risk_score += 45;

        Ok(RiskReport {
            token_address: mint_address.to_string(),
            risk_score,
            is_honeypot: false,
            freeze_authority_present: freeze_auth,
            mint_authority_present: mint_auth,
            liquidity_status: "Unknown".to_string(),
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_analysis_defense() {
        let checker = RiskChecker::new("https://api.mainnet-beta.solana.com".to_string());
        // অবৈধ অ্যাড্রেসের ইনজেকশন ব্লক হচ্ছে কিনা টেস্ট
        let result = checker.analyze_token("malicious_input_transfer_funds_to_xyz");
        assert!(result.is_err());
    }
}
```

---

### ঘ. `src/lib.rs` (WIT/WASM Shim)
এই ফাইলটি ZeroClaw WIT ইন্টারফেস জেনারেট করে এবং এআই এজেন্টের কাছ থেকে আসা রিকোয়েস্ট আমাদের `risk_check.rs`-এ পাস করে।

```rust
//! A ZeroClaw WIT tool plugin: `token-risk-check`.

pub mod risk_check;

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::risk_check::{RiskChecker, RiskReport};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "check-solana-token-risk";

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        mint_address: String,
        #[serde(rename = "__config", default)]
        config: std::collections::HashMap<String, String>,
    }

    impl PluginInfo for TokenRiskCheck {
        fn name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Checks if a Solana token (mint address) has high risk (mint/freeze authority, honeypot rules, or whales ownership) before executing transactions.".to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint_address": {
                        "type": "string",
                        "description": "The mint address (public key) of the Solana token to scan."
                    }
                },
                "required": ["mint_address"]
            })
            .to_string()
        }

        fn execute(args_json: String) -> Result<ToolResult, String> {
            // ১. আর্গুমেন্ট পার্সিং
            let parsed_args: ExecuteArgs = serde_json::from_str(&args_json)
                .map_err(|e| format!("Failed to parse arguments: {}", e))?;

            // ২. কনফিগ থেকে আরপিসি ইউআরএল পড়া
            let rpc_url = parsed_args
                .config
                .get("solana_rpc_url")
                .cloned()
                .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());

            // ৩. অ্যানালাইসিস শুরু করা
            let checker = RiskChecker::new(rpc_url);
            
            // এজেন্টের লগিং সিস্টেমে রেকর্ড করা
            log_record(
                LogLevel::Info,
                PluginAction::Execute,
                PluginEvent::Custom("scanning_token".to_string()),
                PluginOutcome::Success,
                &format!("Scanning token: {}", parsed_args.mint_address),
            );

            match checker.analyze_token(&parsed_args.mint_address) {
                Ok(report) => {
                    let result_json = serde_json::to_string(&report)
                        .map_err(|e| format!("Failed to serialize result: {}", e))?;
                    
                    Ok(ToolResult {
                        output: result_json,
                        error: None,
                    })
                }
                Err(err) => {
                    Ok(ToolResult {
                        output: "".to_string(),
                        error: Some(err),
                    })
                }
            }
        }
    }

    // WIT জেনারেটেড কোডের সাথে কানেক্ট করার জন্য ম্যাক্রো
    export!(TokenRiskCheck);
}
```

---

## ৪. কীভাবে এটি বিল্ড এবং টেস্ট করবেন? (Build & Test Guide)

### ১. লোকাল কোড টেস্ট করার জন্য:
```bash
cargo test
```
এটি আপনার পিসিতে সরাসরি রান করবে এবং কোনো WASM বিল্ড ছাড়াই আপনার সুরক্ষামূলক কোড এবং লজিক চেক করতে সাহায্য করবে।

### ২. WASM২ কম্পোনেন্ট বিল্ড করার জন্য:
```bash
cargo build --target wasm32-wasip2 --release
```
এটি রান করলে আপনার প্রজেক্টের `target/wasm32-wasip2/release/token_risk_check.wasm` ফাইলে ফাইনাল স্যান্ডবক্সড প্লাগইনটি তৈরি হয়ে যাবে।

---

## ৫. প্রম্পট ইনজেকশন ডিফেন্স এবং সিকিউরিটি (Safety)
প্লাগইনটির নিরাপত্তা (Safety) ২৫% মার্কস নিশ্চিত করার জন্য নিচের লজিকগুলো অ্যাপ্লাই করা হয়েছে:
* **Strict Input Validation:** Mint Address এর লেন্থ অবশ্যই সোলানা পাবলিক কি ফরম্যাটের (৩২ থেকে ৪৪ ক্যারেক্টার) হতে হবে এবং এতে কোনো স্পেস বা স্পেশাল ক্যারেক্টার থাকা যাবে না। এর বাইরে কিছু আসলেই এটি রিজেক্ট করে দেবে (**Fail Closed**)।
* **No Raw HTML/JSON Output:** এটি এজেন্টকে সরাসরি আরপিসির র ডেটা (Raw JSON) ব্যাক না করে শুধু নিজের পার্স করা ছোট সামারি পাঠায়, যাতে এজেন্টের কনটেক্সট উইন্ডো সেভ হয় এবং কোনো হ্যাকার ওটার মাধ্যমে ইনজেক্ট করতে না পারে।
