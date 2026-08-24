use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

// ----------------------------------------------------------------------------
// Tier 2: Lingua Token Compressor
// ----------------------------------------------------------------------------

/// Executes Tier 2 token-level extractive compression on structured text or manifests.
/// Attempts to use LLMLingua-2 BERT multilingual model via Python/uv if available,
/// and automatically falls back to the built-in deterministic token pruner if uv is absent.
pub fn run_lingua_compress(input: &str, rate: f32) -> Result<String, String> {
    let uv_bin = which_bin("uv");
    if let Some(uv) = uv_bin {
        let py_script = r#"
import sys
from llmlingua import PromptCompressor
text = sys.stdin.read()
if not text.strip():
    sys.exit(0)
rate = float(sys.argv[1]) if len(sys.argv) > 1 else 0.5
compressor = PromptCompressor(
    model_name="microsoft/llmlingua-2-bert-base-multilingual-meetingbank",
    use_llmlingua2=True,
    device_map="cpu"
)
res = compressor.compress_prompt(
    context=[text],
    rate=rate,
    force_tokens=['\n', '?', '!', ':', '-', '{', '}', '[', ']']
)
print(res['compressed_prompt'])
"#;

        let mut child = Command::new(uv)
            .args(&[
                "run",
                "--with",
                "llmlingua>=0.2.2",
                "--with",
                "torch",
                "--with",
                "transformers",
                "python3",
                "-c",
                py_script,
                &rate.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn uv: {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input.as_bytes());
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("Failed waiting for uv process: {}", e))?;

        if output.status.success() {
            let result = String::from_utf8_lossy(&output.stdout).into_owned();
            if !result.trim().is_empty() {
                return Ok(result);
            }
        }
    }

    Ok(run_builtin_token_pruner(input, rate))
}

/// Fallback deterministic token pruner for environments without Python or PyTorch installed.
/// Removes low-information stop words and redundant tokens while preserving indentation
/// and essential syntax characters across English and Russian text.
pub fn run_builtin_token_pruner(input: &str, target_rate: f32) -> String {
    let mut out = String::new();
    let stopwords: HashMap<&str, ()> = [
        "the", "a", "an", "is", "are", "was", "were", "to", "of", "and", "in", "that", "it",
        "for", "on", "with", "as", "this", "by", "at", "from", "be", "or", "which",
        "и", "в", "на", "с", "по", "для", "к", "о", "из", "что", "это", "как",
    ]
    .iter()
    .cloned()
    .map(|s| (s, ()))
    .collect();

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            out.push('\n');
            continue;
        }

        let indent_len = line.len() - line.trim_start().len();
        let indent = &line[..indent_len];
        out.push_str(indent);

        let words: Vec<&str> = trimmed.split_whitespace().collect();
        if words.len() <= 3 {
            out.push_str(trimmed);
            out.push('\n');
            continue;
        }

        let mut kept_words = Vec::new();
        for (idx, w) in words.iter().enumerate() {
            let lower = w.to_lowercase();
            let clean = lower.trim_matches(|c: char| !c.is_alphanumeric());
            if stopwords.contains_key(clean) && (idx % 2 == 0) && target_rate < 0.8 {
                continue;
            }
            kept_words.push(*w);
        }

        if kept_words.is_empty() {
            out.push_str(trimmed);
        } else {
            out.push_str(&kept_words.join(" "));
        }
        out.push('\n');
    }

    out
}

fn which_bin(name: &str) -> Option<PathBuf> {
    if let Ok(path_var) = std::env::var("PATH") {
        for p in std::env::split_paths(&path_var) {
            let full = p.join(name);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let full = PathBuf::from(home).join(".local/bin").join(name);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_pruner_preserves_indentation() {
        let code = "    let config = load_from_disk(&path);";
        let pruned = run_builtin_token_pruner(code, 0.5);
        assert!(pruned.starts_with("    let config"));
    }
}
