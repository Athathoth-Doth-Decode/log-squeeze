use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const RAW: &str = include_str!("fixtures/secrets.log");
const SAFE: &str = include_str!("fixtures/secrets.redacted.log");
const HEADER: &str = "=== [log-squeeze] Total: 13 lines | Compressed to: 13 events (0.0% reduction) | Errors: 13 | Warnings: 0 ===\n";
const AI_NOTICE: &str = "[log-squeeze: Generating semantic summary via LiteLLM]...\n";
const AI_OUTPUT: &str = "=== [log-squeeze: AI Semantic Summary] ===\n\nSTUB\n";
static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);

impl Sandbox {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "log-squeeze-test-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::create_dir_all(path.join(".config/log-squeeze")).unwrap();
        Self(path)
    }

    fn config(&self, text: &str) {
        fs::write(self.config_path(), text).unwrap();
    }

    fn config_path(&self) -> PathBuf {
        self.0.join(".config/log-squeeze/config.toml")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_log-squeeze"));
        cmd.env_clear()
            .env("HOME", &self.0)
            .env("PATH", self.0.join("bin"));
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    fn run(&self, args: &[&str], input: &str) -> Output {
        run(self.command(args), input)
    }

    // Install a sentinel executable in either supported discovery location.
    // Any invocation records a marker before returning fake compressed text.
    // Tests must prove that local execution leaves the marker absent.
    #[cfg(unix)]
    fn fake_uv(&self, home_bin: bool) {
        use std::os::unix::fs::PermissionsExt;
        let dir = self.0.join(if home_bin { ".local/bin" } else { "bin" });
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("uv");
        fs::write(&path, "#!/bin/bash\nset -euo pipefail\nprintf invoked > \"$HOME/uv-invoked\"\nwhile IFS= read -r line; do printf '%s\\n' \"$line\"; done\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn run(mut cmd: Command, input: &str) -> Output {
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn expect(output: Output, code: i32, stdout: &str, stderr: &str) {
    assert_eq!(output.status.code(), Some(code));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), stdout);
    assert_eq!(String::from_utf8(output.stderr).unwrap(), stderr);
}

fn listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn endpoint(listener: &TcpListener) -> String {
    format!("http://{}/v1", listener.local_addr().unwrap())
}

fn no_connection(listener: &TcpListener) {
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

// Run one local HTTP exchange and retain exactly the bytes the CLI sent.
// Bound accepts and socket reads so a regression fails instead of hanging the suite.
// Respond only with fake data and return parsed headers and the JSON request.
fn serve(
    listener: TcpListener,
    status: u16,
    body: String,
    extra: String,
) -> thread::JoinHandle<(String, Value)> {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "CLI did not connect to the local stub"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("local accept failed: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            headers.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        let length: usize = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .expect("JSON requests must declare their byte length");
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).unwrap();
        let utf8 = String::from_utf8(bytes).unwrap();
        let payload = serde_json::from_str(&utf8).unwrap();
        write!(stream, "HTTP/1.1 {status} Stub\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len()).unwrap();
        (headers, payload)
    })
}

fn stub_body() -> String {
    json!({"choices": [{"message": {"content": "STUB"}}]}).to_string()
}

// Compare every output field with the independently written redacted fixture.
// Exercise local auto, forced fast, JSON and the builtin Tier 2 path.
// The fake uv also proves method=builtin never invokes the neural path.
#[test]
fn redaction_exact_in_all_local_modes() {
    let home = Sandbox::new();
    home.config("[lingua]\nmethod = 'builtin'\n");
    #[cfg(unix)]
    home.fake_uv(false);
    for args in [vec![], vec!["--auto"], vec!["-1"], vec!["-e"]] {
        expect(home.run(&args, RAW), 0, &format!("{HEADER}{SAFE}"), "");
    }
    expect(home.run(&["-2"], RAW), 0, &format!("{SAFE}\n"), "");
    let output = home.run(&["-j"], RAW);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    let expected_clusters: Vec<Value> = SAFE
        .lines()
        .map(|line| {
            json!({
                "template": line, "level": "Error", "count": 1,
                "first_example": line, "last_example": line, "stack_trace": []
            })
        })
        .collect();
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({
            "stats": {"total_lines":13,"output_lines":1,"panics":0,"fatals":0,"errors":13,"warnings":0,"infos":0,"debugs":0,"traces":0,"unknowns":0},
            "clusters_count":13,"clusters":expected_clusters
        })
    );
    assert!(!home.0.join("uv-invoked").exists());
}

// Cover both historical escalation triggers and both executable search locations.
// Configuration enables every external feature with thresholds below the fixture size.
// An idle listener and absent sentinel prove that all configured modes remain local by default.
#[cfg(unix)]
#[test]
fn auto_never_connects_or_runs_uv() {
    let server = listener();
    for home_bin in [false, true] {
        let home = Sandbox::new();
        home.fake_uv(home_bin);
        for mode in ["auto", "ai", "lingua"] {
            home.config(&format!("[general]\nmode='{mode}'\n[litellm]\nenabled=true\nendpoint='{}'\n[lingua]\nenabled=true\n[thresholds]\nmin_lines_for_ai=1\nmin_lines_for_lingua=1\n", endpoint(&server)));
            for flag in [vec![], vec!["--auto"]] {
                for (input, expected) in [
                    (
                        "ERROR password=FAKE_AUTO\n".repeat(120),
                        "=== [log-squeeze] Total: 120 lines | Compressed to: 1 events (99.2% reduction) | Errors: 120 | Warnings: 0 ===\n[x120] [ERROR] ERROR password=<REDACTED> ... [last: ERROR password=<REDACTED>]\n",
                    ),
                    (
                        "kind: Deployment\n".repeat(120),
                        "=== [log-squeeze] Total: 120 lines | Compressed to: 1 events (99.2% reduction) | Errors: 0 | Warnings: 0 ===\n[x120] [LOG] kind: Deployment ... [last: kind: Deployment]\n",
                    ),
                ] {
                    expect(home.run(&flag, &input), 0, expected, "");
                    no_connection(&server);
                    assert!(!home.0.join("uv-invoked").exists());
                }
            }
        }
    }
}

// Keep the existing Java stack representation while suppressing INFO events.
// Use a large input and mode=ai to exercise the former implicit network trigger.
// The idle listener proves that errors-only remains a local filtering operation.
#[test]
fn errors_only_keeps_existing_stack_output_and_never_summarizes() {
    let home = Sandbox::new();
    let server = listener();
    home.config(&format!(
        "[general]\nmode='ai'\n[litellm]\nenabled=true\nendpoint='{}'",
        endpoint(&server)
    ));
    let input = format!(
        "{}ERROR password=FAKE_STACK\n  at example.Main.run(Main.java:42)\n",
        "INFO healthy\n".repeat(120)
    );
    expect(
        home.run(&["-e"], &input),
        0,
        "=== [log-squeeze] Total: 122 lines | Compressed to: 1 events (99.2% reduction) | Errors: 1 | Warnings: 0 ===\nERROR password=<REDACTED>\n  +--- Stack Trace (1 lines):\n  |   at example.Main.run(Main.java:42)\n  +---\n",
        "",
    );
    no_connection(&server);
}

// Invalid combinations must fail before attempting to open the input file.
// Every conflicting pair has one exact diagnostic and no stdout.
// Ordering pipeline flags must never silently change external authorization.
#[test]
fn incompatible_flags_are_rejected() {
    let home = Sandbox::new();
    for args in [
        vec!["-3", "-e"],
        vec!["-e", "-3"],
        vec!["-2", "-e"],
        vec!["-3", "-j"],
        vec!["-3", "-s"],
        vec!["-2", "-j"],
    ] {
        expect(
            home.run(&args, ""),
            1,
            "",
            "Error: --ai/--lingua cannot be combined with --errors-only, --json, or --summary\n",
        );
    }
    expect(
        home.run(&["-e", "-s"], ""),
        1,
        "",
        "Error: --errors-only cannot be combined with --summary\n",
    );
    expect(
        home.run(&["-3", "-a"], ""),
        1,
        "",
        "Error: Conflicting pipeline modes; choose one of --auto, --fast, --lingua, --ai\n",
    );
}

// Assert key precedence using only per-child environments and a loopback stub.
// OPENAI_API_KEY is ignored unless explicitly named in the configuration.
// Each successful request contains exactly the safe log fixture and expected authorization.
#[test]
fn explicit_ai_redacts_and_resolves_only_authorized_key_sources() {
    for (config_key, env, expected_auth) in [
        ("", vec![("OPENAI_API_KEY", "FAKE_OPENAI")], None),
        (
            "",
            vec![
                ("OPENAI_API_KEY", "FAKE_OPENAI"),
                ("LOG_SQUEEZE_API_KEY", "FAKE_DEFAULT"),
            ],
            Some("Bearer FAKE_DEFAULT"),
        ),
        (
            "api_key_env='FAKE_ENV'\n",
            vec![("FAKE_ENV", "FAKE_CUSTOM")],
            Some("Bearer FAKE_CUSTOM"),
        ),
        (
            "api_key_env='OPENAI_API_KEY'\n",
            vec![("OPENAI_API_KEY", "FAKE_EXPLICIT_OPENAI")],
            Some("Bearer FAKE_EXPLICIT_OPENAI"),
        ),
        (
            "api_key='FAKE_CONFIG'\n",
            vec![("LOG_SQUEEZE_API_KEY", "FAKE_DEFAULT")],
            Some("Bearer FAKE_CONFIG"),
        ),
    ] {
        let home = Sandbox::new();
        let server = listener();
        home.config(&format!(
            "[litellm]\nenabled=true\nendpoint='{}'\n{config_key}",
            endpoint(&server)
        ));
        let worker = serve(server, 200, stub_body(), String::new());
        let mut cmd = home.command(&["-3"]);
        cmd.envs(env);
        expect(run(cmd, RAW), 0, AI_OUTPUT, AI_NOTICE);
        let (headers, payload) = worker.join().unwrap();
        assert_eq!(
            headers.lines().next(),
            Some("POST /v1/chat/completions HTTP/1.1")
        );
        let auth = headers.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.trim())
        });
        assert_eq!(auth, expected_auth);
        assert_eq!(
            payload["messages"][1],
            json!({"role":"user","content":format!("{HEADER}{SAFE}")})
        );
    }
}

// Send a multibyte log larger than the request budget through the actual CLI.
// Construct the expected truncated prefix independently of production helpers.
// Compare the exact message and byte count after the stub validates HTTP and UTF-8.
#[test]
fn ai_log_budget_includes_marker_and_preserves_utf8() {
    let home = Sandbox::new();
    let server = listener();
    home.config(&format!(
        "[litellm]\nenabled=true\nendpoint='{}'",
        endpoint(&server)
    ));
    let worker = serve(server, 200, stub_body(), String::new());
    let input = format!("ERROR password=FAKE_LONG {}", "😀я".repeat(10000));
    expect(home.run(&["--ai"], &input), 0, AI_OUTPUT, AI_NOTICE);
    let (_, payload) = worker.join().unwrap();
    let full = format!(
        "=== [log-squeeze] Total: 1 lines | Compressed to: 1 events (0.0% reduction) | Errors: 1 | Warnings: 0 ===\nERROR password=<REDACTED> {}\n",
        "😀я".repeat(10000)
    );
    let marker = "\n[log-squeeze: logs truncated]";
    let mut expected = String::new();
    for c in full.chars() {
        if expected.len() + c.len_utf8() + marker.len() > 32768 {
            break;
        }
        expected.push(c);
    }
    expected.push_str(marker);
    assert_eq!(payload["messages"][1]["content"], expected);
    assert_eq!(expected.len(), 32766);
}

// Force parser, HTTP status and redirect failures using hostile fake response text.
// Diagnostics must never serialize the response body or server-controlled fields.
// A second listener proves that redirects cannot escape endpoint validation.
#[test]
fn ai_errors_are_sanitized_and_redirects_are_not_followed() {
    for (status, body, error) in [
        (
            200,
            "FAKE_SERVER_BODY password=FAKE_ECHO",
            "Invalid LiteLLM JSON response",
        ),
        (
            500,
            "FAKE_SERVER_BODY password=FAKE_ECHO",
            "LiteLLM returned HTTP 500",
        ),
        (302, "FAKE_SERVER_BODY", "LiteLLM returned HTTP 302"),
    ] {
        let home = Sandbox::new();
        let server = listener();
        let redirect = listener();
        home.config(&format!(
            "[litellm]\nenabled=true\nendpoint='{}'\napi_key='FAKE_AUTH'",
            endpoint(&server)
        ));
        let worker = serve(
            server,
            status,
            body.into(),
            format!("Location: {}\r\n", endpoint(&redirect)),
        );
        // A failed summary must not lose the log: Tier 1 output follows the sanitized error.
        expect(
            home.run(&["-3"], RAW),
            0,
            &format!("{HEADER}{SAFE}"),
            &format!("{AI_NOTICE}[log-squeeze: {error}; showing Tier 1 output]\n"),
        );
        worker.join().unwrap();
        no_connection(&redirect);
    }
}

// Reject deceptive hosts before any DNS lookup or connection can occur.
// Point proxy environment variables at a local trap to expose accidental transport use.
// Even absent input must not take precedence over the insecure endpoint error.
#[test]
fn keyed_http_non_loopback_is_rejected_before_transport() {
    let home = Sandbox::new();
    let proxy = listener();
    for endpoint in [
        "http://localhost.evil.example/v1",
        "http://127.0.0.1.evil.example/v1",
        "http://192.0.2.1/v1",
        "http://[::2]/v1",
        "http://[::ffff:192.0.2.1]/v1",
    ] {
        let mut cmd = home.command(&[
            "-3",
            "--endpoint",
            endpoint,
            "--key",
            "FAKE_HTTP_KEY",
            "/missing/input",
        ]);
        cmd.env("HTTP_PROXY", super_proxy(&proxy));
        expect(
            run(cmd, ""),
            1,
            "",
            "Error: Refusing to send API key over HTTP to a non-loopback endpoint; use HTTPS\n",
        );
        no_connection(&proxy);
    }
}

fn super_proxy(listener: &TcpListener) -> String {
    format!("http://{}", listener.local_addr().unwrap())
}

// Cover absent, unreadable, malformed and semantically invalid configurations.
// Invalid source text includes a fake secret and must never appear in diagnostics.
// A missing input filename proves configuration failure happens before input processing.
#[test]
fn config_loading_is_strict_without_writing_defaults() {
    let home = Sandbox::new();
    expect(home.run(&["-1"], RAW), 0, &format!("{HEADER}{SAFE}"), "");
    assert!(!home.config_path().exists());
    let missing = home.0.join("missing.toml");
    expect(
        home.run(&["--config", missing.to_str().unwrap()], ""),
        1,
        "",
        &format!(
            "Error: Cannot read config '{}': entity not found\n",
            missing.display()
        ),
    );
    for (config, reason) in [
        (
            "[general]\nmax_lines='FAKE_CONFIG_SECRET'\n[litellm]\nenabled=false",
            "at line 2: invalid TOML, field, or value type",
        ),
        (
            "FAKE_CONFIG_SECRET = [",
            "at line 1: invalid TOML, field, or value type",
        ),
        (
            "unknown='FAKE_CONFIG_SECRET'",
            "at line 1: invalid TOML, field, or value type",
        ),
        (
            "[general]\nmode='FAKE_CONFIG_SECRET'",
            ": general.mode must be auto, fast, lingua, or ai",
        ),
        (
            "[general]\nmax_lines=0",
            ": general.max_lines must be positive",
        ),
        (
            "[lingua]\nrate=nan",
            ": lingua.rate must be finite and in (0, 1]",
        ),
    ] {
        home.config(config);
        let separator = if reason.starts_with(':') { "" } else { " " };
        expect(
            home.run(&["/missing/input"], ""),
            1,
            "",
            &format!(
                "Error: Invalid config '{}'{}{}\n",
                home.config_path().display(),
                separator,
                reason
            ),
        );
        assert_eq!(fs::read_to_string(home.config_path()).unwrap(), config);
    }
    fs::remove_file(home.config_path()).unwrap();
    fs::create_dir(home.config_path()).unwrap();
    expect(
        home.run(&["/missing/input"], ""),
        1,
        "",
        &format!(
            "Error: Cannot read config '{}': is a directory\n",
            home.config_path().display()
        ),
    );
}

// Force a permission error on the actual standard config path.
// Root test runners drop privileges only for this child so permission semantics stay real.
// Restore permissions after the assertion so sandbox cleanup remains deterministic.
#[cfg(unix)]
#[test]
fn unreadable_and_dangling_configs_fail_closed() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::process::CommandExt;
    let home = Sandbox::new();
    home.config("[litellm]\nenabled=false");
    fs::set_permissions(home.config_path(), fs::Permissions::from_mode(0o000)).unwrap();
    let mut cmd = home.command(&["/missing/input"]);
    if fs::metadata(&home.0).unwrap().uid() == 0 {
        cmd.uid(65534);
    }
    let output = run(cmd, "");
    fs::set_permissions(home.config_path(), fs::Permissions::from_mode(0o600)).unwrap();
    expect(
        output,
        1,
        "",
        &format!(
            "Error: Cannot read config '{}': permission denied\n",
            home.config_path().display()
        ),
    );
    fs::remove_file(home.config_path()).unwrap();
    symlink(home.0.join("missing-target"), home.config_path()).unwrap();
    expect(
        home.run(&[], ""),
        1,
        "",
        &format!(
            "Error: Cannot read config '{}': entity not found\n",
            home.config_path().display()
        ),
    );
}

// Exercise explicit key override and the localhost pin through a real local request.
// Hostile proxy settings must not receive even loopback traffic or authorization.
// Redact both labeled response secrets and an unlabeled echo of the request key.
#[test]
fn localhost_ignores_proxies_and_response_cannot_echo_key() {
    let home = Sandbox::new();
    let server = listener();
    let proxy = listener();
    let port = server.local_addr().unwrap().port();
    home.config(&format!(
        "[litellm]\nenabled=true\nendpoint='http://localhost:{port}/v1'\napi_key='FAKE_CONFIG'"
    ));
    let body =
        json!({"choices":[{"message":{"content":"FAKE_CLI password=FAKE_RESPONSE"}}]}).to_string();
    let worker = serve(server, 200, body, String::new());
    let mut cmd = home.command(&["-3", "--key", "FAKE_CLI"]);
    cmd.env("HTTP_PROXY", super_proxy(&proxy))
        .env("ALL_PROXY", super_proxy(&proxy));
    expect(
        run(cmd, RAW),
        0,
        "=== [log-squeeze: AI Semantic Summary] ===\n\n<REDACTED> password=<REDACTED>\n",
        AI_NOTICE,
    );
    let (headers, _) = worker.join().unwrap();
    assert_eq!(
        headers
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            .unwrap(),
        "authorization: Bearer FAKE_CLI"
    );
    no_connection(&proxy);
}

// Call Tier 2 explicitly with a harmless executable instead of any real dependencies.
// Its stdout echoes stdin, proving redaction precedes the subprocess boundary.
// The sentinel confirms this path remains available only for the explicit flag.
#[cfg(unix)]
#[test]
fn explicit_lingua_receives_only_redacted_input() {
    let home = Sandbox::new();
    home.config("[lingua]\nenabled=true");
    home.fake_uv(true);
    expect(home.run(&["-2"], RAW), 0, &format!("{SAFE}\n"), "");
    assert_eq!(
        fs::read_to_string(home.0.join("uv-invoked")).unwrap(),
        "invoked"
    );
}

// Verify summary templates and stack examples also cross the redaction boundary.
// This single-template case checks redaction independently of frequency ordering.
// Exact output prevents missing fields from hiding a secret-retention regression.
#[test]
fn templates_and_stack_examples_are_redacted() {
    let home = Sandbox::new();
    expect(
        home.run(&["-s"], "ERROR password=FAKE_TEMPLATE\n"),
        0,
        "=== [log-squeeze] Total: 1 lines | Compressed to: 1 events (0.0% reduction) | Errors: 1 | Warnings: 0 ===\n\n--- Top Repeating Templates ---\n[x    1] ERROR password=<REDACTED>\n",
        "",
    );
    expect(
        home.run(
            &["-e"],
            "ERROR password=FAKE_ERROR\n  at fake.call token=FAKE_FRAME\n",
        ),
        0,
        "=== [log-squeeze] Total: 2 lines | Compressed to: 1 events (50.0% reduction) | Errors: 1 | Warnings: 0 ===\nERROR password=<REDACTED>\n  +--- Stack Trace (1 lines):\n  |   at fake.call token=<REDACTED>\n  +---\n",
        "",
    );
}

// Reproduce the reviewed bypasses through every local renderer and the HTTP boundary.
// Expected strings are independent of the redactor, including the JSON escape spelling.
// Check both EOF-truncated input and newline-terminated input with isolated fake-only services.
#[test]
fn redaction_bypass_regressions_in_stdout_and_ai_request() {
    let cases = [
        (
            "password: FAKE_FIRST&FAKE_SECOND",
            "password: <REDACTED>",
            "Unknown",
            0,
            1,
        ),
        (
            "password: FAKE_FIRST?token=FAKE_SECOND&FAKE_LAST",
            "password: <REDACTED>",
            "Unknown",
            0,
            1,
        ),
        (
            r#"ERROR password="FAKE_UNTERMINATED"#,
            r#"ERROR password="<REDACTED>"#,
            "Error",
            1,
            0,
        ),
        (
            "ERROR password='FAKE_UNTERMINATED",
            "ERROR password='<REDACTED>",
            "Error",
            1,
            0,
        ),
        (
            r#"{"url":"postgres:\/\/fake:FAKE_PASSWORD@db\/app"}"#,
            r#"{"url":"postgres:\/\/<REDACTED>@db\/app"}"#,
            "Unknown",
            0,
            1,
        ),
        (
            r#"{"url":"mongodb+srv:\/\/fake:FAKE_PASSWORD@db\/app"}"#,
            r#"{"url":"mongodb+srv:\/\/<REDACTED>@db\/app"}"#,
            "Unknown",
            0,
            1,
        ),
        (
            r#"{"url":"redis:\/\/:FAKE_PASSWORD@cache"}"#,
            r#"{"url":"redis:\/\/<REDACTED>@cache"}"#,
            "Unknown",
            0,
            1,
        ),
    ];
    for (raw, safe, level, errors, unknowns) in cases {
        for ending in ["", "\n"] {
            let home = Sandbox::new();
            let server = listener();
            home.config(&format!(
                "[lingua]\nmethod='builtin'\n[litellm]\nenabled=true\nendpoint='{}'",
                endpoint(&server)
            ));
            let input = format!("{raw}{ending}");
            let header = format!(
                "=== [log-squeeze] Total: 1 lines | Compressed to: 1 events (0.0% reduction) | Errors: {errors} | Warnings: 0 ===\n"
            );
            let output = format!("{header}{safe}\n");
            for args in [vec!["-1"], vec![], vec!["--auto"]] {
                expect(home.run(&args, &input), 0, &output, "");
            }
            expect(home.run(&["-2"], &input), 0, &format!("{safe}\n\n"), "");
            expect(
                home.run(&["-s"], &input),
                0,
                &format!("{header}\n--- Top Repeating Templates ---\n[x    1] {safe}\n"),
                "",
            );
            let json_output = home.run(&["-j"], &input);
            assert_eq!(json_output.status.code(), Some(0));
            assert_eq!(json_output.stderr, b"");
            assert_eq!(
                serde_json::from_slice::<Value>(&json_output.stdout).unwrap(),
                json!({
                    "stats": {"total_lines":1,"output_lines":1,"panics":0,"fatals":0,"errors":errors,"warnings":0,"infos":0,"debugs":0,"traces":0,"unknowns":unknowns},
                    "clusters_count":1,
                    "clusters":[{"template":safe,"level":level,"count":1,"first_example":safe,"last_example":safe,"stack_trace":[]}]
                })
            );
            no_connection(&server);
            let worker = serve(server, 200, stub_body(), String::new());
            expect(home.run(&["-3"], &input), 0, AI_OUTPUT, AI_NOTICE);
            let (_, payload) = worker.join().unwrap();
            assert_eq!(
                payload["messages"][1],
                json!({"role":"user","content":output})
            );
        }
    }
}

// Compare literal expected output before and after redacting the same input again.
// Retain independent expected templates so masking numbers cannot hide deleted diagnostics.
// A local HTTP stub verifies that Tier 3 receives the identical redacted event and neighbors.
fn assert_context_boundary(raw: &str, safe: &str, template: &str, error: bool) {
    let home = Sandbox::new();
    let server = listener();
    home.config(&format!(
        "[litellm]\nenabled=true\nendpoint='{}'",
        endpoint(&server)
    ));
    let (level, errors, unknowns) = if error {
        ("Error", 1, 0)
    } else {
        ("Unknown", 0, 1)
    };
    let header = format!(
        "=== [log-squeeze] Total: 1 lines | Compressed to: 1 events (0.0% reduction) | Errors: {errors} | Warnings: 0 ===\n"
    );
    let stdout = format!("{header}{safe}\n");
    for input in [raw.to_owned(), format!("{raw}\n"), safe.to_owned()] {
        for args in [vec!["-1"], vec!["--auto"]] {
            expect(home.run(&args, &input), 0, &stdout, "");
        }
        let output = home.run(&["-j"], &input);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stderr, b"");
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!({
                "stats": {"total_lines":1,"output_lines":1,"panics":0,"fatals":0,"errors":errors,"warnings":0,"infos":0,"debugs":0,"traces":0,"unknowns":unknowns},
                "clusters_count":1,
                "clusters":[{"template":template,"level":level,"count":1,"first_example":safe,"last_example":safe,"stack_trace":[]}]
            })
        );
    }
    no_connection(&server);
    let worker = serve(server, 200, stub_body(), String::new());
    expect(home.run(&["-3"], raw), 0, AI_OUTPUT, AI_NOTICE);
    let (_, payload) = worker.join().unwrap();
    assert_eq!(
        payload["messages"][1],
        json!({"role":"user","content":stdout})
    );
}

// Flow-style YAML passwords can include multiple words and punctuation.
// Neighboring mapping entries must remain present in stdout, JSON and the AI request.
// Test quoted values and several secrets as well as the exact reported reproduction.
#[test]
fn yaml_flow_boundaries_in_stdout_and_ai_request() {
    for (raw, safe, template) in [
        (
            "credentials: {password: FAKE_FIRST FAKE_SECOND, user: app}",
            "credentials: {password: <REDACTED>, user: app}",
            "credentials: {password: <REDACTED>, user: app}",
        ),
        (
            "credentials: { password : FAKE_FIRST & FAKE_SECOND , user : app }",
            "credentials: { password : <REDACTED> , user : app }",
            "credentials: { password : <REDACTED> , user : app }",
        ),
        (
            r#"credentials: {password: "FAKE_FIRST,code=500 & SECOND", user: app}"#,
            r#"credentials: {password: "<REDACTED>", user: app}"#,
            r#"credentials: {password: "<REDACTED>", user: app}"#,
        ),
        (
            "credentials: {user: app, password: FAKE_FIRST FAKE_SECOND, token: FAKE_TOKEN & tail, code: 500}",
            "credentials: {user: app, password: <REDACTED>, token: <REDACTED>, code: 500}",
            "credentials: {user: app, password: <REDACTED>, token: <REDACTED>, code: 500}",
        ),
    ] {
        assert_context_boundary(raw, safe, template, false);
    }
}

// Unquoted log fields may be comma-separated without spaces.
// Preserve code, path and user while still removing punctuation inside each password.
// Quoted comma-assignment sequences must stay inside the secret rather than becoming fields.
#[test]
fn diagnostic_field_boundaries_in_stdout_and_ai_request() {
    for (raw, safe, template) in [
        (
            "ERROR password=FAKE_PASSWORD,code=500,path=/checkout user=app",
            "ERROR password=<REDACTED>,code=500,path=/checkout user=app",
            "ERROR password=<REDACTED>,code=500,path=/checkout user=app",
        ),
        (
            "ERROR password = FAKE_PASSWORD , code = 500 , path = /checkout user=app",
            "ERROR password = <REDACTED> , code = 500 , path = /checkout user=app",
            "ERROR password = <REDACTED> , code = 500 , path = /checkout user=app",
        ),
        (
            "ERROR password=FAKE_FIRST&FAKE_SECOND,code=500,path=/checkout user=app",
            "ERROR password=<REDACTED>,code=500,path=/checkout user=app",
            "ERROR password=<REDACTED>,code=500,path=/checkout user=app",
        ),
        (
            "ERROR password=FAKE_FIRST,FAKE_SECOND;FAKE_THIRD,code=500,path=/checkout user=app",
            "ERROR password=<REDACTED>,code=500,path=/checkout user=app",
            "ERROR password=<REDACTED>,code=500,path=/checkout user=app",
        ),
        (
            r#"ERROR password="FAKE_FIRST,code=500 & SECOND",code=500,path=/checkout user=app"#,
            r#"ERROR password="<REDACTED>",code=500,path=/checkout user=app"#,
            r#"ERROR password="<REDACTED>",code=500,path=/checkout user=app"#,
        ),
        (
            "ERROR password=FAKE_PASSWORD,token=FAKE_TOKEN,code=500,path=/checkout user=app",
            "ERROR password=<REDACTED>,token=<REDACTED>,code=500,path=/checkout user=app",
            "ERROR password=<REDACTED>,token=<REDACTED>,code=500,path=/checkout user=app",
        ),
    ] {
        assert_context_boundary(raw, safe, template, true);
    }
}

// A single-quoted YAML path must not swallow the context of a later password.
// Exercise a literal backslash and a doubled apostrophe next to structural punctuation.
// Check exact local output, idempotence, JSON and the actual Tier 3 request body.
#[test]
fn yaml_single_quote_path_in_stdout_and_ai_request() {
    for (raw, safe) in [
        (
            r"credentials: {path: 'C:\', password: FAKE_FIRST FAKE_SECOND, user: app}",
            r"credentials: {path: 'C:\', password: <REDACTED>, user: app}",
        ),
        (
            r"credentials: {path: 'C:\''}, still path', password: FAKE_FIRST FAKE_SECOND, user: app}",
            r"credentials: {path: 'C:\''}, still path', password: <REDACTED>, user: app}",
        ),
        (
            r#"credentials: {path: "C:\\", password: FAKE_FIRST FAKE_SECOND, user: app}"#,
            r#"credentials: {path: "C:\\", password: <REDACTED>, user: app}"#,
        ),
    ] {
        assert_context_boundary(raw, safe, safe, false);
    }
}

// A single-quoted YAML password ending in backslash must preserve following fields.
// Both the password and the later token must be independently redacted.
// Run the exact report and a doubled-apostrophe variant through the CLI and local HTTP stub.
#[test]
fn yaml_single_quote_secret_in_stdout_and_ai_request() {
    for (raw, safe) in [
        (
            r"credentials: {password: 'FAKE\', user: app, token: FAKE_TOKEN}",
            "credentials: {password: '<REDACTED>', user: app, token: <REDACTED>}",
        ),
        (
            r"credentials: {password: 'FAKE\''SECOND', user: app, token: FAKE_TOKEN}",
            "credentials: {password: '<REDACTED>', user: app, token: <REDACTED>}",
        ),
    ] {
        assert_context_boundary(raw, safe, safe, false);
    }
    assert_context_boundary(
        r"ERROR password='FAKE\'SECOND',code=500 user=app",
        "ERROR password='<REDACTED>',code=500 user=app",
        "ERROR password='<REDACTED>',code=500 user=app",
        true,
    );
}

// Exercise the complete language fixture through errors-only output and filtered JSON.
// A handwritten golden file specifies every stack line, separator and redacted secret.
// Auto must remain local even with an enabled endpoint and these crash-heavy logs.
#[test]
fn language_stacks_cli_golden_and_json() {
    let home = Sandbox::new();
    let server = listener();
    home.config(&format!(
        "[litellm]\nenabled=true\nendpoint='{}'",
        endpoint(&server)
    ));
    let input = include_str!("fixtures/events/traces.log");
    let golden = include_str!("fixtures/events/traces.errors.txt");
    for args in [vec!["-e"], vec!["-1", "-e"], vec!["--auto", "-e"]] {
        expect(home.run(&args, input), 0, golden, "");
    }
    let output = home.run(&["-j", "-e"], input);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let expected: Value =
        serde_json::from_str(include_str!("fixtures/events/traces.errors.json")).unwrap();
    assert_eq!(json, expected);
    no_connection(&server);
}

// Kernel OOM and crash diagnostics are errors even without an explicit log level.
// Explicit INFO and JSON/logfmt severities still take precedence over message keywords.
// Check the complete errors-only output so false positives cannot silently slip through.
#[test]
fn levels_and_kernel_errors_cli() {
    let home = Sandbox::new();
    let input = "INFO no panic detected\nlevel=info msg=\"warning\"\n{\"level\":30,\"msg\":\"error\"}\nGET /api/errors 200\nkernel: Out of memory: Killed process 42 (worker)\nkernel: worker[42]: segfault at 0\npod terminated: OOMKilled\n";
    expect(
        home.run(&["-e"], input),
        0,
        "=== [log-squeeze] Total: 7 lines | Compressed to: 3 events (57.1% reduction) | Errors: 3 | Warnings: 0 ===\nkernel: Out of memory: Killed process 42 (worker)\nkernel: worker[42]: segfault at 0\npod terminated: OOMKilled\n",
        "",
    );
}

// Reproduce all three second-stage review findings through actual CLI output.
// A handwritten golden preserves Python source/pointers, Node properties and new klog events.
// Errors-only filtering must neither drop bare Java exceptions nor promote INFO messages to panic.
#[test]
fn second_stage_review_regressions_cli_golden() {
    let home = Sandbox::new();
    let input = include_str!("fixtures/events/review-regressions.log");
    let golden = include_str!("fixtures/events/review-regressions.errors.txt");
    for args in [vec!["-e"], vec!["-1", "-e"], vec!["--auto", "-e"]] {
        expect(home.run(&args, input), 0, golden, "");
    }
    let output = home.run(&["-j", "-e"], input);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let expected: Value = serde_json::from_str(include_str!(
        "fixtures/events/review-regressions.errors.json"
    ))
    .unwrap();
    assert_eq!(json, expected);
}

// The CLI must apply the same selection to text and JSON after secret redaction.
// Configuration supplies the budget while explicit overrides can reduce it further.
// Enabled external settings and a fake uv cannot turn budget pressure into network execution.
#[test]
fn budget_cli_preserves_order_json_and_local_auto() {
    let home = Sandbox::new();
    let server = listener();
    home.config(&format!(
        "[general]\nmode='ai'\nmax_lines=4\n[litellm]\nenabled=true\nendpoint='{}'",
        endpoint(&server)
    ));
    #[cfg(unix)]
    home.fake_uv(true);
    let input = "INFO alpha\nDEBUG beta\nERROR gamma password=FAKE_BUDGET\nINFO delta\nWARN epsilon\nINFO zeta\n";
    let expected = "=== [log-squeeze] Total: 6 lines | Compressed to: 6 events (0.0% reduction) | Errors: 1 | Warnings: 1 ===\nINFO alpha\n[... 1 events skipped] ERROR gamma password=<REDACTED>\n[... 1 events skipped] WARN epsilon [... 1 events skipped]\n";
    for args in [vec![], vec!["-1"], vec!["--auto", "-m", "4"]] {
        expect(home.run(&args, input), 0, expected, "");
    }
    let output = home.run(&["-j"], input);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    assert_eq!(
        std::str::from_utf8(&output.stdout).unwrap().lines().count(),
        1
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({
            "stats":{"total_lines":6,"output_lines":1,"panics":0,"fatals":0,"errors":1,"warnings":1,"infos":3,"debugs":1,"traces":0,"unknowns":0},
            "clusters_count":3,
            "clusters":[
                {"template":"INFO alpha","level":"Info","count":1,"first_example":"INFO alpha","last_example":"INFO alpha","stack_trace":[]},
                {"template":"ERROR gamma password=<REDACTED>","level":"Error","count":1,"first_example":"ERROR gamma password=<REDACTED>","last_example":"ERROR gamma password=<REDACTED>","stack_trace":[],"skipped_before":1},
                {"template":"WARN epsilon","level":"Warn","count":1,"first_example":"WARN epsilon","last_example":"WARN epsilon","stack_trace":[],"skipped_before":1}
            ],
            "budget":{"skipped_events":3,"skipped_clusters":3,"skipped_after":1,"omitted_stack_lines":0,"omitted_templates":0}
        })
    );
    expect(
        home.run(&["-e", "-m", "2"], input),
        0,
        "=== [log-squeeze] Total: 6 lines | Compressed to: 2 events (66.7% reduction) | Errors: 1 | Warnings: 1 ===\nERROR gamma password=<REDACTED> [... 1 events skipped]\n",
        "",
    );
    no_connection(&server);
    assert!(!home.0.join("uv-invoked").exists());
}

// Stack truncation must be visible in both human output and structured cluster metadata.
// A one-line budget can print only the header, which still reports all omitted data.
// Zero is rejected before opening the input file rather than silently exceeding the cap.
#[test]
fn stack_budget_cli_reports_truncation_and_validates_zero() {
    let home = Sandbox::new();
    let input = "ERROR failed\n    at app.One.run(One.java:1)\n    at app.Two.run(Two.java:2)\n    at app.Three.run(Three.java:3)\n    at app.Four.run(Four.java:4)\n";
    let header = "=== [log-squeeze] Total: 5 lines | Compressed to: 1 events (80.0% reduction) | Errors: 1 | Warnings: 0 ===";
    expect(
        home.run(&["-e", "-m", "4"], input),
        0,
        &format!(
            "{header}\nERROR failed [... 2 stack lines omitted]\n  |     at app.One.run(One.java:1)\n  |     at app.Two.run(Two.java:2)\n"
        ),
        "",
    );
    let output = home.run(&["-j", "-e", "-m", "4"], input);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({
            "stats":{"total_lines":5,"output_lines":1,"panics":0,"fatals":0,"errors":1,"warnings":0,"infos":0,"debugs":0,"traces":0,"unknowns":0},
            "clusters_count":1,
            "clusters":[{"template":"ERROR failed","level":"Error","count":1,"first_example":"ERROR failed","last_example":"ERROR failed","stack_trace":["    at app.One.run(One.java:1)","    at app.Two.run(Two.java:2)"],"omitted_stack_lines":2}],
            "budget":{"skipped_events":0,"skipped_clusters":0,"skipped_after":0,"omitted_stack_lines":2,"omitted_templates":0}
        })
    );
    expect(
        home.run(&["-e", "-m", "1"], input),
        0,
        &format!("{header} [... 1 events skipped] [... 4 stack lines omitted]\n"),
        "",
    );
    let output = home.run(&["-j", "-m", "1"], input);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, b"");
    assert_eq!(
        std::str::from_utf8(&output.stdout).unwrap().lines().count(),
        1
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({
            "stats":{"total_lines":5,"output_lines":1,"panics":0,"fatals":0,"errors":1,"warnings":0,"infos":0,"debugs":0,"traces":0,"unknowns":0},
            "clusters_count":0,"clusters":[],
            "budget":{"skipped_events":1,"skipped_clusters":1,"skipped_after":1,"omitted_stack_lines":4,"omitted_templates":0}
        })
    );
    expect(
        home.run(&["-m", "0", "/missing/input"], ""),
        1,
        "",
        "Error: general.max_lines must be positive\n",
    );
}

// Summary ties use a fixed lexical order across separate CLI processes.
// Both metadata and template rows count toward the physical line cap.
// Small numeric error codes must remain distinct in this mode as well.
#[test]
fn summary_cli_has_stable_ties_and_hard_budget() {
    let home = Sandbox::new();
    let input = "ERROR code=14\nINFO zebra\nERROR code=13\nINFO alpha\n";
    for _ in 0..3 {
        expect(
            home.run(&["-s", "-m", "5"], input),
            0,
            "=== [log-squeeze] Total: 4 lines | Compressed to: 4 events (0.0% reduction) | Errors: 2 | Warnings: 0 ===\n\n--- Top Repeating Templates ---\n[x    1] ERROR code=13\n[x    1] ERROR code=14 [... 2 templates omitted]\n",
            "",
        );
    }
}

// Tier 3 and the uv subprocess need both the explicit flag and the config opt-in.
// Disabled sections must not open sockets or spawn uv, and output stays exact Tier 1/builtin text.
// The notices name the disabling field so a user can tell why no summary appeared.
#[test]
fn disabled_tiers_never_leave_the_process() {
    let home = Sandbox::new();
    let server = listener();
    home.config(&format!(
        "[litellm]\nenabled=false\nendpoint='{}'\n[lingua]\nenabled=false",
        endpoint(&server)
    ));
    home.fake_uv(true);
    expect(
        home.run(&["-3"], RAW),
        0,
        &format!("{HEADER}{SAFE}"),
        "[log-squeeze: litellm.enabled = false; showing Tier 1 output]\n",
    );
    no_connection(&server);
    let output = home.run(&["-2"], RAW);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "[log-squeeze: lingua.enabled = false; using the built-in pruner without subprocesses]\n"
    );
    assert!(!home.0.join("uv-invoked").exists());
}

// Unreachable endpoints are a transport error, not a reason to drop the log.
#[test]
fn unreachable_ai_endpoint_falls_back_to_tier1() {
    let home = Sandbox::new();
    let server = listener();
    let address = endpoint(&server);
    drop(server);
    home.config(&format!("[litellm]\nenabled=true\nendpoint='{address}'"));
    expect(
        home.run(&["-3"], RAW),
        0,
        &format!("{HEADER}{SAFE}"),
        &format!(
            "{AI_NOTICE}[log-squeeze: LiteLLM request failed (transport or redirect error); showing Tier 1 output]\n"
        ),
    );
}

// Invalid UTF-8 bytes are replaced with U+FFFD instead of rejecting the whole log.
#[test]
fn invalid_utf8_input_is_processed_lossily() {
    let home = Sandbox::new();
    let mut child = home.command(&[]).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"ERROR bad byte \xff here\n")
        .unwrap();
    expect(
        child.wait_with_output().unwrap(),
        0,
        "=== [log-squeeze] Total: 1 lines | Compressed to: 1 events (0.0% reduction) | Errors: 1 | Warnings: 0 ===\nERROR bad byte \u{fffd} here\n",
        "",
    );
}
