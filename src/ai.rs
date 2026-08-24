use crate::config::AppConfig;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::Duration;

// ----------------------------------------------------------------------------
// Tier 3: LiteLLM Semantic Analyzer
// ----------------------------------------------------------------------------

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct ChatCompletionRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessageResponse,
}

#[derive(Deserialize)]
struct ChatMessageResponse {
    content: String,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
}

/// Executes Tier 3 semantic root-cause analysis via an OpenAI-compatible endpoint.
/// Formats a strict SRE diagnostic prompt, submits the squeezed logs to LiteLLM/Ollama/OpenAI,
/// and returns a concise 4-point markdown incident report.
pub fn run_litellm_summary(squeezed_text: &str, cfg: &AppConfig) -> Result<String, String> {
    let api_key = cfg.get_litellm_api_key().unwrap_or_default();
    let url = format!("{}/chat/completions", cfg.litellm.endpoint.trim_end_matches('/'));

    let system_prompt = "You are an expert SRE, cloud infrastructure and systems diagnostic agent. \
Analyze the provided squeezed logs and produce a concise, structured markdown report with the following sections:
1. **Root Cause & Summary**: What failed and why.
2. **Key Events & Timeline**: Concise sequence of critical events.
3. **Critical Verbatim Lines**: 2-4 exact log error lines in quotes.
4. **Actionable Recommendations**: Clear troubleshooting steps.
Be direct, highly technical, and avoid fluff or conversational filler.";

    let payload = ChatCompletionRequest {
        model: &cfg.litellm.model,
        messages: vec![
            ChatMessage {
                role: "system",
                content: system_prompt,
            },
            ChatMessage {
                role: "user",
                content: squeezed_text,
            },
        ],
        max_tokens: cfg.litellm.max_tokens,
        temperature: cfg.litellm.temperature,
    };

    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(cfg.litellm.timeout_secs)))
        .build()
        .new_agent();

    let mut req = agent.post(&url);
    if !api_key.is_empty() {
        req = req.header("Authorization", &format!("Bearer {}", api_key));
    }
    req = req.header("Content-Type", "application/json");

    let resp = req
        .send_json(&payload)
        .map_err(|e| format!("LiteLLM request error ({}): {}", url, e))?;

    let mut body_str = String::new();
    resp.into_body()
        .into_reader()
        .read_to_string(&mut body_str)
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    let parsed: ChatCompletionResponse = serde_json::from_str(&body_str)
        .map_err(|e| format!("Failed to parse JSON response: {}. Raw: {}", e, body_str))?;

    if let Some(choice) = parsed.choices.into_iter().next() {
        Ok(choice.message.content)
    } else {
        Err("Empty choices in LiteLLM response".to_string())
    }
}
