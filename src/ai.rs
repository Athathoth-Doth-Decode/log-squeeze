use crate::config::AppConfig;
use crate::redact::redact;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::Duration;
use url::{Host, Url};

// ----------------------------------------------------------------------------
// Tier 3: LiteLLM Semantic Analyzer
// ----------------------------------------------------------------------------

// WHY: Borrow prompt text during serialization without cloning the log buffer.
#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

// WHY: The request borrows configuration and redacted text only until the send completes.
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

pub const MAX_LOG_BYTES: usize = 32 * 1024;
pub const TRUNCATION_MARKER: &str = "\n[log-squeeze: logs truncated]";

/// Parse the destination before making any connection or resolving a hostname.
/// HTTP credentials are allowed only for loopback IPs or the exact localhost name.
/// Pin localhost to a loopback IP and reject URL credentials, queries and fragments.
pub fn validate_endpoint(endpoint: &str, has_key: bool) -> Result<Url, String> {
    let mut url = Url::parse(endpoint).map_err(|_| "Invalid LiteLLM endpoint URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err("LiteLLM endpoint must be an absolute HTTP(S) URL".into());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("LiteLLM endpoint must not contain credentials, query, or fragment".into());
    }
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(name)) => matches!(name, "localhost" | "localhost."),
        None => false,
    };
    if has_key && url.scheme() == "http" && !loopback {
        return Err(
            "Refusing to send API key over HTTP to a non-loopback endpoint; use HTTPS".into(),
        );
    }
    if url.scheme() == "http"
        && matches!(url.host(), Some(Host::Domain("localhost" | "localhost.")))
    {
        url.set_host(Some("127.0.0.1"))
            .map_err(|_| "Invalid loopback endpoint")?;
    }
    Ok(url)
}

/// Redact before imposing the request budget so truncation cannot expose partial secrets.
/// The budget counts UTF-8 bytes in the log message, including the explicit marker.
/// Move the cut to a character boundary to preserve valid Unicode.
pub fn prepare_logs(input: &str) -> String {
    let mut text = redact(input);
    if text.len() > MAX_LOG_BYTES {
        let mut end = MAX_LOG_BYTES - TRUNCATION_MARKER.len();
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str(TRUNCATION_MARKER);
    }
    text
}

/// Executes Tier 3 semantic root-cause analysis via an OpenAI-compatible endpoint.
/// Formats a strict SRE diagnostic prompt, submits the squeezed logs to LiteLLM/Ollama/OpenAI,
/// and returns a concise 4-point markdown incident report.
pub fn run_litellm_summary(squeezed_text: &str, cfg: &AppConfig) -> Result<String, String> {
    let api_key = cfg.get_litellm_api_key().unwrap_or_default();
    let mut url = validate_endpoint(&cfg.litellm.endpoint, !api_key.is_empty())?;
    url.set_path(&format!(
        "{}/chat/completions",
        url.path().trim_end_matches('/')
    ));
    let text = if api_key.is_empty() {
        squeezed_text.to_owned()
    } else {
        squeezed_text.replace(&api_key, "<REDACTED>")
    };
    let text = prepare_logs(&text);

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
                content: &text,
            },
        ],
        max_tokens: cfg.litellm.max_tokens,
        temperature: cfg.litellm.temperature,
    };

    let agent = ureq::Agent::config_builder()
        // Do not let redirects or environment proxies bypass destination validation.
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(cfg.litellm.timeout_secs)))
        .build()
        .new_agent();

    let mut req = agent.post(url.as_str());
    if !api_key.is_empty() {
        req = req.header("Authorization", &format!("Bearer {}", api_key));
    }
    req = req.header("Content-Type", "application/json");

    let resp = req.send_json(&payload).map_err(|e| match e {
        ureq::Error::StatusCode(code) => format!("LiteLLM returned HTTP {}", code),
        _ => "LiteLLM request failed (transport or redirect error)".to_string(),
    })?;
    if !resp.status().is_success() {
        return Err(format!("LiteLLM returned HTTP {}", resp.status().as_u16()));
    }

    let mut body_str = String::new();
    resp.into_body()
        .into_reader()
        .take(1024 * 1024 + 1)
        .read_to_string(&mut body_str)
        .map_err(|_| "Failed to read LiteLLM response body")?;
    if body_str.len() > 1024 * 1024 {
        return Err("LiteLLM response exceeds 1 MiB".into());
    }

    let parsed: ChatCompletionResponse =
        serde_json::from_str(&body_str).map_err(|_| "Invalid LiteLLM JSON response")?;

    if let Some(choice) = parsed.choices.into_iter().next() {
        let content = if api_key.is_empty() {
            choice.message.content
        } else {
            choice.message.content.replace(&api_key, "<REDACTED>")
        };
        Ok(redact(&content))
    } else {
        Err("Empty choices in LiteLLM response".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Parse genuine loopbacks and hostile lookalikes without opening sockets.
    // URL normalization is allowed only when the parsed IP is actually loopback.
    // Every rejected destination has one exact safe error message.
    #[test]
    fn loopback_url_policy() {
        for (input, expected) in [
            ("http://localhost/v1", "http://127.0.0.1/v1"),
            ("http://LOCALHOST.:8080/v1", "http://127.0.0.1:8080/v1"),
            ("http://127.0.0.2/v1", "http://127.0.0.2/v1"),
            ("http://[::1]/v1", "http://[::1]/v1"),
            ("http://127.1/v1", "http://127.0.0.1/v1"),
            ("https://example.invalid/v1", "https://example.invalid/v1"),
        ] {
            assert_eq!(validate_endpoint(input, true).unwrap().as_str(), expected);
        }
        for input in [
            "http://localhost.evil.example/v1",
            "http://127.0.0.1.evil.example/v1",
            "http://[::]/v1",
            "http://192.0.2.1/v1",
        ] {
            assert_eq!(
                validate_endpoint(input, true).unwrap_err(),
                "Refusing to send API key over HTTP to a non-loopback endpoint; use HTTPS"
            );
        }
        for input in [
            "https://fake:FAKE_SECRET@localhost/v1",
            "http://localhost/v1?token=FAKE",
            "http://localhost/v1#FAKE",
        ] {
            assert_eq!(
                validate_endpoint(input, true).unwrap_err(),
                "LiteLLM endpoint must not contain credentials, query, or fragment"
            );
        }
        assert_eq!(
            validate_endpoint("FAKE_INVALID_URL", true).unwrap_err(),
            "Invalid LiteLLM endpoint URL"
        );
    }

    // Check both sides of the exact byte boundary independently of CLI rendering.
    // A secret crossing the cutoff must be removed before truncation is considered.
    // Short input and input exactly at the limit remain byte-for-byte unchanged.
    #[test]
    fn request_budget_boundaries_and_redaction_order() {
        for length in [0, MAX_LOG_BYTES - 1, MAX_LOG_BYTES] {
            let text = "x".repeat(length);
            assert_eq!(prepare_logs(&text), text);
        }
        assert_eq!(
            prepare_logs(&"x".repeat(MAX_LOG_BYTES + 1)),
            format!(
                "{}{}",
                "x".repeat(MAX_LOG_BYTES - TRUNCATION_MARKER.len()),
                TRUNCATION_MARKER
            )
        );
        let input = format!("password={} useful", "FAKE_SECRET".repeat(MAX_LOG_BYTES));
        assert_eq!(prepare_logs(&input), "password=<REDACTED> useful");
    }
}
