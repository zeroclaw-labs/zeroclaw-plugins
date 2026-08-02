//! Pure fal.ai request/response logic — no wasm dependency.
//!
//! Everything that can be decided without performing I/O lives here so it
//! compiles and tests on the host with a plain `cargo test`. The wasm component
//! in [`crate`] is a thin shim that adds config lookup and the HTTP call.

use std::collections::HashMap;

/// Default fal.ai model when the caller does not name one.
pub const DEFAULT_MODEL: &str = "fal-ai/flux/schnell";

/// Config key holding the fal.ai API key, read from this plugin's own
/// config section (`config_read`).
pub const API_KEY_FIELD: &str = "api_key";

/// Image size presets fal.ai accepts.
pub const VALID_SIZES: &[&str] = &[
    "square_hd",
    "landscape_4_3",
    "portrait_4_3",
    "landscape_16_9",
    "portrait_16_9",
];

const DEFAULT_SIZE: &str = "square_hd";

/// A validated generation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenRequest {
    pub prompt: String,
    pub size: String,
    pub model: String,
}

impl GenRequest {
    /// The fal.ai endpoint this request posts to.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("https://fal.run/{}", self.model)
    }

    /// JSON body for the fal.ai call.
    #[must_use]
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "prompt": self.prompt,
            "image_size": self.size,
            "num_images": 1,
        })
    }
}

/// Validate and normalize the tool's JSON arguments.
///
/// `__config` is ignored here; the API key is resolved separately by
/// [`api_key`] so a malformed key never masks an argument error.
///
/// # Errors
/// Returns a user-facing message when `prompt` is missing/blank, `size` is not
/// a known preset, or `model` is not a plausible fal.ai model path.
pub fn parse_args(args: &serde_json::Value) -> Result<GenRequest, String> {
    let prompt = args
        .get("prompt")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or("Missing required parameter: 'prompt'")?
        .to_string();

    let size = args
        .get("size")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SIZE);
    if !VALID_SIZES.contains(&size) {
        return Err(format!(
            "Invalid size '{size}'. Valid values: {}",
            VALID_SIZES.join(", ")
        ));
    }

    let model = args
        .get("model")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_MODEL);
    validate_model(model)?;

    Ok(GenRequest {
        prompt,
        size: size.to_string(),
        model: model.to_string(),
    })
}

/// Reject model identifiers that could escape the fal.run path or smuggle a
/// query/fragment onto the request URL.
fn validate_model(model: &str) -> Result<(), String> {
    let bad = model.contains("..")
        || model.contains('?')
        || model.contains('#')
        || model.contains('\\')
        || model.starts_with('/');
    if bad {
        return Err(format!(
            "Invalid model identifier '{model}'. \
             Must be a fal.ai model path (e.g. '{DEFAULT_MODEL}')."
        ));
    }
    Ok(())
}

/// Resolve the fal.ai API key from this plugin's injected config section.
///
/// # Errors
/// Returns a user-facing message when the key is absent or blank. The message
/// names the config path rather than an env var: raw environment access was
/// removed from plugins, and the key now lives in the plugin's own config.
pub fn api_key(config: &HashMap<String, String>) -> Result<String, String> {
    match config.get(API_KEY_FIELD).map(|k| k.trim()) {
        Some(k) if !k.is_empty() => Ok(k.to_string()),
        _ => Err(format!(
            "Missing fal.ai API key. Set `{API_KEY_FIELD}` in this plugin's \
             config section (plugins.entries.image-gen-fal.config)."
        )),
    }
}

/// Extract the generated image URL from a fal.ai response body.
///
/// # Errors
/// Returns a user-facing message when the body is not JSON or carries no image.
pub fn parse_response(body: &str) -> Result<String, String> {
    let json: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("failed to parse fal.ai response: {e}"))?;
    json.pointer("/images/0/url")
        .and_then(serde_json::Value::as_str)
        .filter(|u| !u.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| "no image URL in fal.ai response".to_string())
}

/// Truncate an upstream error body so a huge HTML error page cannot flood the
/// agent's context window.
#[must_use]
pub fn truncate_error(body: &str, status: u16) -> String {
    let clipped: String = body.chars().take(500).collect();
    format!("fal.ai API error ({status}): {clipped}")
}

/// Human-readable success summary handed back to the model.
#[must_use]
pub fn success_output(req: &GenRequest, image_url: &str) -> String {
    format!(
        "Image generated successfully.\nModel: {}\nPrompt: {}\nImage URL: {image_url}",
        req.model, req.prompt
    )
}

/// JSON Schema for the tool's parameters.
#[must_use]
pub fn parameters_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["prompt"],
        "properties": {
            "prompt": {
                "type": "string",
                "description": "Text prompt describing the image to generate."
            },
            "size": {
                "type": "string",
                "enum": VALID_SIZES,
                "description": format!("Image aspect ratio / size preset (default: '{DEFAULT_SIZE}')."),
            },
            "model": {
                "type": "string",
                "description": format!("fal.ai model identifier (default: '{DEFAULT_MODEL}')."),
            }
        }
    })
}
