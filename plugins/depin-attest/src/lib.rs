pub mod provenance;
pub mod reading;

#[cfg(target_family = "wasm")]
mod shim {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;

    struct DepinAttestPlugin;

    impl PluginInfo for DepinAttestPlugin {
        fn plugin_name() -> String {
            "depin-attest".to_string()
        }

        fn plugin_version() -> String {
            "0.1.0".to_string()
        }
    }

    impl Tool for DepinAttestPlugin {
        fn name() -> String {
            "depin-attest".to_string()
        }

        fn description() -> String {
            "Verify Ed25519 signatures of DePIN sensor readings.".to_string()
        }

        fn parameters_schema() -> String {
            "{}".to_string()
        }

        fn execute(_args: String) -> Result<ToolResult, String> {
            Ok(ToolResult {
                success: false,
                output: "".to_string(),
                error: Some("Not implemented yet".to_string()),
            })
        }
    }

    export!(DepinAttestPlugin);
}
