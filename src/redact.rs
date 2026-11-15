//! Secret removal shared by all tiers, including direct library calls.
use regex::Regex;
use std::sync::LazyLock;

pub const REDACTED: &str = "<REDACTED>";

static URL_CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(\b[a-z][a-z0-9+.-]*:(?:\\?/){2})[^\s/@?#"'<>]+@"#).unwrap()
});
static AUTHORIZATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(\bauthorization["']?[ \t]*[:=][ \t]*["']?(?:bearer|basic)[ \t]+)(?:<REDACTED>|[^\s"',;\]}<>]+)"#).unwrap()
});
const SECRET_KEY: &str = r"(?:aws[_-])?(?:secret[_-]access[_-]key|access[_-]key(?:[_-]id)?|secret[_-]key|session[_-]token)|password|passwd|pwd|secret|(?:access[_-]|refresh[_-])?token|api[_-]?key|access[_-]?key";
static FIELD_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)(?P<query>[?&])?\b(?:{SECRET_KEY})\b["']?[ \t]*(?P<separator>[:=])[ \t]*"#
    ))
    .unwrap()
});
static LOG_NEXT_FIELD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^,[ \t]*[a-zA-Z_][a-zA-Z0-9_.-]*[ \t]*=").unwrap());

#[derive(Clone, Copy)]
enum ValueContext {
    Query,
    YamlBlock,
    YamlFlow,
    Log,
}

#[derive(Clone, Copy)]
struct QuoteRules {
    delimiter: u8,
    backslash_escapes: bool,
}

impl QuoteRules {
    fn new(delimiter: u8, context: ValueContext) -> Self {
        Self {
            delimiter,
            backslash_escapes: delimiter == b'"'
                || !matches!(context, ValueContext::YamlBlock | ValueContext::YamlFlow),
        }
    }
}

#[derive(Default)]
struct FlowState {
    containers: Vec<u8>,
    quote: Option<QuoteRules>,
    escaped: bool,
    previous: Option<u8>,
    field_separator: Option<u8>,
}

impl FlowState {
    fn advance(&mut self, text: &str) {
        for byte in text.bytes() {
            self.observe(byte);
        }
    }

    fn in_flow(&self) -> bool {
        !self.containers.is_empty() && self.quote.is_none()
    }

    /// Track flow containers without treating punctuation inside strings as syntax.
    /// YAML single quotes use doubled apostrophes, while double quotes and log fields retain backslash escapes.
    /// Reset on line endings because truncated log events must not affect the next event.
    fn observe(&mut self, byte: u8) {
        if matches!(byte, b'\r' | b'\n') {
            *self = Self::default();
            return;
        }
        if let Some(quote) = self.quote {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' && quote.backslash_escapes {
                self.escaped = true;
            } else if byte == quote.delimiter {
                self.quote = None;
            }
        } else {
            match byte {
                b'"' | b'\''
                    if self.previous.is_none_or(|previous| {
                        previous.is_ascii_whitespace()
                            || matches!(previous, b'{' | b'[' | b',' | b':' | b'=')
                            || previous == byte
                    }) =>
                {
                    let context =
                        if self.containers.is_empty() || self.field_separator == Some(b'=') {
                            ValueContext::Log
                        } else {
                            ValueContext::YamlFlow
                        };
                    self.quote = Some(QuoteRules::new(byte, context));
                }
                b'{' | b'[' => {
                    self.containers.push(byte);
                    self.field_separator = None;
                }
                b'}' if self.containers.last() == Some(&b'{') => {
                    self.containers.pop();
                    self.field_separator = None;
                }
                b']' if self.containers.last() == Some(&b'[') => {
                    self.containers.pop();
                    self.field_separator = None;
                }
                b':' | b'=' => self.field_separator = Some(byte),
                b',' => self.field_separator = None,
                _ => {}
            }
        }
        self.previous = Some(byte);
    }
}

static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+={0,2}").unwrap()
});
static AWS_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b").unwrap());

/// Remove credential values before any processing or transport.
/// Retain keys, quotes, delimiters and URL destinations so logs stay useful.
/// Recognize our own marker to make repeated redaction stable.
pub fn redact(input: &str) -> String {
    let text = URL_CREDENTIALS.replace_all(input, "${1}<REDACTED>@");
    let text = AUTHORIZATION.replace_all(&text, "${1}<REDACTED>");
    let text = redact_fields(&text);
    let text = JWT.replace_all(&text, REDACTED);
    AWS_ACCESS_KEY.replace_all(&text, REDACTED).into_owned()
}

/// Consume each complete field value before looking for another field prefix.
/// Query separators apply only to query fields, while block YAML uses the whole plain scalar.
/// Skipping consumed values prevents a nested token= fragment from exposing the rest of a password.
fn redact_fields(input: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    let mut syntax = FlowState::default();
    for caps in FIELD_PREFIX.captures_iter(input) {
        let prefix = caps.get(0).unwrap();
        if prefix.start() < cursor {
            continue;
        }
        let preceding = &input[cursor..prefix.end()];
        output.push_str(preceding);
        syntax.advance(preceding);
        let value = &input[prefix.end()..];
        let context = if caps.name("query").is_some() {
            ValueContext::Query
        } else if &caps["separator"] == ":" && syntax.in_flow() {
            ValueContext::YamlFlow
        } else if is_yaml_scalar(input, prefix.start(), &caps["separator"]) {
            ValueContext::YamlBlock
        } else {
            ValueContext::Log
        };
        let (length, replacement) = redact_value(value, context);
        output.push_str(&replacement);
        // Consumed secret text cannot change the context of a neighboring field.
        syntax.advance(&replacement);
        cursor = prefix.end() + length;
    }
    output.push_str(&input[cursor..]);
    output
}

fn is_yaml_scalar(input: &str, start: usize, separator: &str) -> bool {
    let before = input[..start].rsplit('\n').next().unwrap_or("").trim();
    let before = before.trim_end_matches(['\'', '"']).trim_end();
    separator == ":" && matches!(before, "" | "-")
}

/// Choose value boundaries from the field's quoting and syntax context.
/// An unfinished quote consumes the rest of its line but never the next event.
/// Preserve existing quotes and YAML comments without synthesizing missing delimiters.
fn redact_value(value: &str, context: ValueContext) -> (usize, String) {
    if let Some(quote @ ('"' | '\'')) = value.chars().next() {
        let (end, closed) = quoted_value_end(value, QuoteRules::new(quote as u8, context));
        let suffix = if closed {
            quote.to_string()
        } else {
            String::new()
        };
        return (end, format!("{quote}{REDACTED}{suffix}"));
    }
    let end = match context {
        ValueContext::YamlBlock => yaml_block_end(value),
        ValueContext::YamlFlow => yaml_flow_end(value),
        ValueContext::Query => value
            .find(|c: char| c.is_whitespace() || matches!(c, '&' | '#' | '"' | '\''))
            .unwrap_or(value.len()),
        ValueContext::Log => log_value_end(value),
    };
    let replacement = if end == 0 {
        String::new()
    } else {
        REDACTED.to_owned()
    };
    (end, replacement)
}

fn yaml_block_end(value: &str) -> usize {
    let line = value.split(['\r', '\n']).next().unwrap_or("");
    let comment = line
        .char_indices()
        .find_map(|(i, c)| {
            (c == '#' && (i == 0 || line[..i].ends_with(char::is_whitespace))).then_some(i)
        })
        .unwrap_or(line.len());
    line[..comment].trim_end().len()
}

/// Keep spaces and punctuation inside a flow scalar until its actual structural separator.
/// Nested collections and their quoted contents are consumed as one value when necessary.
/// Leave the separating comma, closing container and surrounding whitespace in the output.
fn yaml_flow_end(value: &str) -> usize {
    let mut syntax = FlowState::default();
    let mut end = value.len();
    for (i, byte) in value.bytes().enumerate() {
        let unquoted = syntax.quote.is_none();
        let separator =
            unquoted && syntax.containers.is_empty() && matches!(byte, b',' | b'}' | b']');
        let comment = unquoted
            && byte == b'#'
            && syntax
                .previous
                .is_none_or(|previous| previous.is_ascii_whitespace());
        if matches!(byte, b'\r' | b'\n') || separator || comment {
            end = i;
            break;
        }
        syntax.observe(byte);
    }
    value[..end].trim_end().len()
}

/// Recognize comma-separated log assignments without splitting punctuation-only passwords.
/// A comma is structural only when the following text is another key=value assignment.
/// Quoted values bypass this rule so literal comma-assignment sequences remain secret.
fn log_value_end(value: &str) -> usize {
    let end = value
        .char_indices()
        .find_map(|(i, c)| {
            (c.is_whitespace()
                || matches!(c, '"' | '\'')
                || (c == ',' && LOG_NEXT_FIELD.is_match(&value[i..])))
            .then_some(i)
        })
        .unwrap_or(value.len());
    value[..end].trim_end_matches(['}', ']', ')']).len()
}

/// Find a closing quote using the same context-specific escape rules as the flow lexer.
/// Scan ASCII syntax bytes so returned boundaries cannot split a UTF-8 character.
/// Missing delimiters and trailing backslashes safely end at a newline or end of input.
fn quoted_value_end(value: &str, rules: QuoteRules) -> (usize, bool) {
    let bytes = value.as_bytes();
    let mut i = 1;
    while i < bytes.len() && !matches!(bytes[i], b'\r' | b'\n') {
        if rules.backslash_escapes
            && bytes[i] == b'\\'
            && i + 1 < bytes.len()
            && !matches!(bytes[i + 1], b'\r' | b'\n')
        {
            i += 2;
        } else if bytes[i] == rules.delimiter {
            if rules.delimiter == b'\'' && bytes.get(i + 1) == Some(&rules.delimiter) {
                i += 2;
            } else {
                return (i + 1, true);
            }
        } else {
            i += 1;
        }
    }
    (i, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A backslash is literal inside a YAML single-quoted diagnostic value.
    // Closing that value must restore mapping context before a later password is scanned.
    // Doubled apostrophes remain inside the value, including beside braces and commas.
    #[test]
    fn yaml_single_quote_path_preserves_mapping_context() {
        for (raw, safe) in [
            (
                r"credentials: {path: 'C:\', password: FAKE_FIRST FAKE_SECOND, user: app}",
                r"credentials: {path: 'C:\', password: <REDACTED>, user: app}",
            ),
            (
                r"credentials: {path: 'C:\it''s\', password: FAKE_FIRST & FAKE_SECOND, user: app}",
                r"credentials: {path: 'C:\it''s\', password: <REDACTED>, user: app}",
            ),
            (
                r"credentials: {path: 'C:\''}, still path', password: FAKE_FIRST FAKE_SECOND, user: app}",
                r"credentials: {path: 'C:\''}, still path', password: <REDACTED>, user: app}",
            ),
        ] {
            assert_eq!(redact(raw), safe);
            assert_eq!(redact(safe), safe);
        }
    }

    // A YAML password ending in backslash must still end at the following apostrophe.
    // Preserve neighboring user fields and redact each later secret independently.
    // Cover doubled apostrophes and block YAML with the same quoting rules.
    #[test]
    fn yaml_single_quote_secret_preserves_neighbors() {
        for (raw, safe) in [
            (
                r"credentials: {password: 'FAKE\', user: app, token: FAKE_TOKEN}",
                "credentials: {password: '<REDACTED>', user: app, token: <REDACTED>}",
            ),
            (
                r"credentials: {password: 'FAKE\''SECOND', user: app, token: FAKE_TOKEN}",
                "credentials: {password: '<REDACTED>', user: app, token: <REDACTED>}",
            ),
            (
                r"credentials: {password: 'FAKE''SECOND\', user: app, token: 'FAKE_TOKEN\'}",
                "credentials: {password: '<REDACTED>', user: app, token: '<REDACTED>'}",
            ),
            (
                r"password: 'FAKE\' # keep comment",
                "password: '<REDACTED>' # keep comment",
            ),
        ] {
            assert_eq!(redact(raw), safe);
            assert_eq!(redact(safe), safe);
        }
    }

    // Double quotes retain backslash escapes in YAML and ordinary logs.
    // Single-quoted log fields also retain the existing backslash-escape convention.
    // Verify both secret scanning and lexical context after an escaped diagnostic value.
    #[test]
    fn double_quotes_and_log_single_quotes_keep_backslash_escapes() {
        for (raw, safe) in [
            (
                r#"credentials: {path: "C:\\", password: FAKE_FIRST FAKE_SECOND, user: app}"#,
                r#"credentials: {path: "C:\\", password: <REDACTED>, user: app}"#,
            ),
            (
                r#"credentials: {password: "FAKE\"SECOND", user: app, token: FAKE_TOKEN}"#,
                r#"credentials: {password: "<REDACTED>", user: app, token: <REDACTED>}"#,
            ),
            (
                r"ERROR password='FAKE\'SECOND',code=500 user=app",
                "ERROR password='<REDACTED>',code=500 user=app",
            ),
            (
                r#"ERROR password="FAKE\"SECOND",code=500 user=app"#,
                r#"ERROR password="<REDACTED>",code=500 user=app"#,
            ),
            (
                r"ERROR msg='literal\' {brace' password='FAKE\'SECOND',code=500 user=app",
                r"ERROR msg='literal\' {brace' password='<REDACTED>',code=500 user=app",
            ),
            (
                r"ERROR {msg='literal\' {brace', password='FAKE\'SECOND',code=500} user=app",
                r"ERROR {msg='literal\' {brace', password='<REDACTED>',code=500} user=app",
            ),
        ] {
            assert_eq!(redact(raw), safe);
            assert_eq!(redact(safe), safe);
        }
    }

    // Exercise common credentials and delimiters with exact expected output.
    // Fake secrets cover both ordinary logs and quoted structured values.
    // Running each result twice also guards the shared tier boundaries.
    #[test]
    fn exact_redaction_is_idempotent() {
        let cases = [
            (
                "Authorization: Bearer fake.bearer tail",
                "Authorization: Bearer <REDACTED> tail",
            ),
            (
                r#"{"Authorization": "Basic ZmFrZTpmYWtl", "ok": true}"#,
                r#"{"Authorization": "Basic <REDACTED>", "ok": true}"#,
            ),
            (
                "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.ZmFrZXNpZw end",
                "jwt=<REDACTED> end",
            ),
            (
                "postgres://fake:pass@db/app mongodb+srv://fake:pass@db/app redis://:pass@cache https://fake@host/x",
                "postgres://<REDACTED>@db/app mongodb+srv://<REDACTED>@db/app redis://<REDACTED>@cache https://<REDACTED>@host/x",
            ),
            (
                "AKIAIOSFODNN7EXAMPLE ASIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalr/fake+key= next",
                "<REDACTED> <REDACTED> AWS_SECRET_ACCESS_KEY=<REDACTED> next",
            ),
            (
                "password=one passwd: two pwd='three four' secret=abc",
                "password=<REDACTED> passwd: <REDACTED> pwd='<REDACTED>' secret=<REDACTED>",
            ),
            (
                "/x?token=abc&api_key=def&api-key=ghi&access_key=jkl#anchor",
                "/x?token=<REDACTED>&api_key=<REDACTED>&api-key=<REDACTED>&access_key=<REDACTED>#anchor",
            ),
            (
                r#"{"password":"fake\"secret", "token": "two words", "ok": 42}"#,
                r#"{"password":"<REDACTED>", "token": "<REDACTED>", "ok": 42}"#,
            ),
            (
                "api-key: 'it''s fake' # keep\npassword: \"two words\"\nuseful text",
                "api-key: '<REDACTED>' # keep\npassword: \"<REDACTED>\"\nuseful text",
            ),
            (
                "AWS_ACCESS_KEY_ID=FAKE_ID AWS_SESSION_TOKEN=FAKE_SESSION",
                "AWS_ACCESS_KEY_ID=<REDACTED> AWS_SESSION_TOKEN=<REDACTED>",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(redact(input), expected);
            assert_eq!(redact(expected), expected);
        }
    }
    // Query punctuation must not split secrets in ordinary fields or YAML scalars.
    // Keep real query separators and YAML comments outside the secret value.
    // Assert idempotence because every pipeline can redact the same text repeatedly.
    #[test]
    fn plain_secrets_and_query_values_have_distinct_boundaries() {
        for (input, expected) in [
            ("password: FAKE_FIRST&FAKE_SECOND", "password: <REDACTED>"),
            (
                r#"{"message":"password=FAKE_FIRST&FAKE_SECOND","ok":true}"#,
                r#"{"message":"password=<REDACTED>","ok":true}"#,
            ),
            (
                "[last: ERROR password=FAKE_WORD]",
                "[last: ERROR password=<REDACTED>]",
            ),
            (
                "password: FAKE_FIRST,FAKE_SECOND;FAKE_THIRD}FAKE_LAST",
                "password: <REDACTED>",
            ),
            (
                "  password: FAKE FIRST & SECOND # useful comment",
                "  password: <REDACTED> # useful comment",
            ),
            (
                "ERROR password=FAKE_FIRST&FAKE_SECOND useful",
                "ERROR password=<REDACTED> useful",
            ),
            (
                "password=FAKE_FIRST&token=FAKE_SECOND&FAKE_LAST",
                "password=<REDACTED>",
            ),
            (
                "url=/path?password=FAKE_FIRST&ok=yes#anchor",
                "url=/path?password=<REDACTED>&ok=yes#anchor",
            ),
            (
                "password: FAKE_FIRST?token=FAKE_SECOND&FAKE_LAST",
                "password: <REDACTED>",
            ),
        ] {
            assert_eq!(redact(input), expected);
            assert_eq!(redact(expected), expected);
        }
    }

    // Truncated logs must not bypass redaction merely because a quote is missing.
    // Consume the incomplete value through the line ending without swallowing the next event.
    // Preserve the original quoting shape and keep repeated redaction stable.
    #[test]
    fn unterminated_quoted_secrets_are_redacted() {
        for (input, expected) in [
            (
                r#"ERROR password="FAKE_UNTERMINATED"#,
                r#"ERROR password="<REDACTED>"#,
            ),
            (
                "ERROR password='FAKE_UNTERMINATED",
                "ERROR password='<REDACTED>",
            ),
            (
                r#"ERROR password="FAKE\"ESCAPED"#,
                r#"ERROR password="<REDACTED>"#,
            ),
            (
                r#"ERROR password="FAKE_TRAILING\"#,
                r#"ERROR password="<REDACTED>"#,
            ),
            (
                "password: \"FAKE FIRST\r\nINFO useful",
                "password: \"<REDACTED>\r\nINFO useful",
            ),
            (
                r#"{"password":"FAKE_UNTERMINATED"#,
                r#"{"password":"<REDACTED>"#,
            ),
        ] {
            assert_eq!(redact(input), expected);
            assert_eq!(redact(expected), expected);
        }
    }

    // JSON permits escaped slashes in URL strings without changing URL semantics.
    // Preserve the representation and useful destination while removing all userinfo.
    // Parse the result as JSON and check that a second pass makes no changes.
    #[test]
    fn json_escaped_url_credentials_are_redacted() {
        for (input, expected) in [
            (
                r#"{"url":"postgres:\/\/fake:FAKE_PASSWORD@db\/app"}"#,
                r#"{"url":"postgres:\/\/<REDACTED>@db\/app"}"#,
            ),
            (
                r#"{"url":"mongodb+srv:\/\/fake:FAKE_PASSWORD@db\/app"}"#,
                r#"{"url":"mongodb+srv:\/\/<REDACTED>@db\/app"}"#,
            ),
            (
                r#"{"url":"redis:\/\/:FAKE_PASSWORD@cache"}"#,
                r#"{"url":"redis:\/\/<REDACTED>@cache"}"#,
            ),
            (
                r#"{"url":"https:/\/fake:FAKE_PASSWORD@host\/path"}"#,
                r#"{"url":"https:/\/<REDACTED>@host\/path"}"#,
            ),
        ] {
            assert_eq!(redact(input), expected);
            assert_eq!(redact(expected), expected);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&redact(input)).unwrap(),
                serde_json::from_str::<serde_json::Value>(expected).unwrap()
            );
        }
    }
    // Flow mappings delimit plain scalar values with commas and closing brackets.
    // Spaces and ampersands within a scalar belong to the secret, not a new field.
    // Quoting and nesting must preserve adjacent diagnostic fields on repeated passes.
    #[test]
    fn yaml_flow_mapping_value_boundaries() {
        for (raw, safe) in [
            (
                "credentials: {password: FAKE_FIRST FAKE_SECOND, user: app}",
                "credentials: {password: <REDACTED>, user: app}",
            ),
            (
                "credentials: { password : FAKE_FIRST & FAKE_SECOND , user : app }",
                "credentials: { password : <REDACTED> , user : app }",
            ),
            (
                r#"credentials: {password: "FAKE_FIRST,code=500 & SECOND", user: app}"#,
                r#"credentials: {password: "<REDACTED>", user: app}"#,
            ),
            (
                "credentials: {password: 'FAKE_FIRST,code=500 & SECOND', user: app}",
                "credentials: {password: '<REDACTED>', user: app}",
            ),
            (
                "credentials: {user: app, password: FAKE_FIRST FAKE_SECOND, token: FAKE_TOKEN & tail, code: 500}",
                "credentials: {user: app, password: <REDACTED>, token: <REDACTED>, code: 500}",
            ),
            (
                "credentials: {db: {password: FAKE_FIRST FAKE_SECOND, user: app}, path: /checkout}",
                "credentials: {db: {password: <REDACTED>, user: app}, path: /checkout}",
            ),
            (
                r#"credentials: {note: "literal } and ,", "password": FAKE_FIRST FAKE_SECOND, user: app}"#,
                r#"credentials: {note: "literal } and ,", "password": <REDACTED>, user: app}"#,
            ),
            (
                "credentials: [{password: FAKE_FIRST FAKE_SECOND, user: app}]",
                "credentials: [{password: <REDACTED>, user: app}]",
            ),
            ("password: FAKE_FIRST&FAKE_SECOND", "password: <REDACTED>"),
            (
                "password: FAKE_FIRST,code=500;FAKE_SECOND & FAKE_LAST",
                "password: <REDACTED>",
            ),
        ] {
            assert_eq!(redact(raw), safe);
            assert_eq!(redact(safe), safe);
        }
    }

    // In unquoted log fields a comma before key=value starts the next field.
    // Commas without an assignment and punctuation inside quotes remain part of the password.
    // Verify that repeated redaction retains every neighboring code, path and user field.
    #[test]
    fn log_field_boundaries_preserve_diagnostics() {
        for (raw, safe) in [
            (
                "ERROR password=FAKE_PASSWORD,code=500,path=/checkout user=app",
                "ERROR password=<REDACTED>,code=500,path=/checkout user=app",
            ),
            (
                "ERROR password = FAKE_PASSWORD , code = 500 , path = /checkout user=app",
                "ERROR password = <REDACTED> , code = 500 , path = /checkout user=app",
            ),
            (
                "ERROR password=FAKE_FIRST&FAKE_SECOND,code=500,path=/checkout user=app",
                "ERROR password=<REDACTED>,code=500,path=/checkout user=app",
            ),
            (
                "ERROR password=FAKE_FIRST,FAKE_SECOND;FAKE_THIRD,code=500,path=/checkout user=app",
                "ERROR password=<REDACTED>,code=500,path=/checkout user=app",
            ),
            (
                "ERROR password=FAKE_PASSWORD;&,code=500 user=app",
                "ERROR password=<REDACTED>,code=500 user=app",
            ),
            (
                "ERROR password=FAKE_PASSWORD,; user=app",
                "ERROR password=<REDACTED> user=app",
            ),
            (
                r#"ERROR password="FAKE_FIRST,code=500 & SECOND",code=500,path=/checkout user=app"#,
                r#"ERROR password="<REDACTED>",code=500,path=/checkout user=app"#,
            ),
            (
                "ERROR password='FAKE_FIRST,code=500 & SECOND',code=500,path=/checkout user=app",
                "ERROR password='<REDACTED>',code=500,path=/checkout user=app",
            ),
            (
                "ERROR password=FAKE_PASSWORD,token=FAKE_TOKEN,code=500,path=/checkout user=app",
                "ERROR password=<REDACTED>,token=<REDACTED>,code=500,path=/checkout user=app",
            ),
            (
                r#"ERROR msg="literal { brace" password=FAKE_FIRST,FAKE_SECOND,code=500 user=app"#,
                r#"ERROR msg="literal { brace" password=<REDACTED>,code=500 user=app"#,
            ),
        ] {
            assert_eq!(redact(raw), safe);
            assert_eq!(redact(safe), safe);
        }
    }
}
