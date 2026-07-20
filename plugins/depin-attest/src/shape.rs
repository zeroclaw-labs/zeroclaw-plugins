//! Response shaping: the LLM gets ~200 tokens, never the 40KB the RPC sent.
/// Rough token cap ~= 4 chars/token heuristic; hard-truncate with ellipsis.
pub const MAX_OUTPUT_CHARS: usize = 800;

pub fn cap(s: &str) -> String {
    if s.len() <= MAX_OUTPUT_CHARS {
        s.to_owned()
    } else {
        let mut end = MAX_OUTPUT_CHARS;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}
