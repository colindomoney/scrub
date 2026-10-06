use crate::cli::Sensitivity;
use crate::config::ResolvedConfig;
use crate::entropy::high_entropy_tokens;
use crate::patterns::named_patterns;

#[derive(Debug, Clone)]
pub enum MatchKind {
    NamedPattern(&'static str),
    CustomPattern(String),
    HighEntropyToken,
}

#[derive(Debug, Clone)]
pub struct Match {
    pub line_no: usize,    // 1-based
    pub byte_start: usize, // within the line string
    pub byte_end: usize,
    pub kind: MatchKind,
    pub entropy: Option<f64>,
}

impl Match {
    pub fn matched_len(&self) -> usize {
        self.byte_end - self.byte_start
    }
}

pub fn scan_lines(text: &str, config: &ResolvedConfig) -> Vec<Match> {
    let mut all_matches: Vec<Match> = Vec::new();

    for (line_idx, line) in text.lines().enumerate() {
        let line_no = line_idx + 1;

        // Allowlist: skip entire line if any allowlist string appears in it
        if config.allowlist.iter().any(|a| line.contains(a.as_str())) {
            continue;
        }

        let mut line_matches: Vec<Match> = Vec::new();

        // Named patterns
        for (label, lazy_re) in named_patterns() {
            let re = &**lazy_re;
            for caps in re.captures_iter(line) {
                // Patterns with capture groups redact only the first group that
                // participated (e.g. the value, not the key name).
                let m = caps
                    .iter()
                    .skip(1)
                    .flatten()
                    .next()
                    .unwrap_or_else(|| caps.get(0).unwrap());
                // URLs under secret-named keys (`token_url`, `secret_endpoint`)
                // are config, not secrets.
                if *label == "Secret-named key" && m.as_str().contains("://") {
                    continue;
                }
                // Filter out false-positive "Base64 Blob" matches that are
                // actually file paths: paths contain '/' but never '+' or '='.
                if *label == "Base64 Blob 40+" {
                    let matched = &line[m.start()..m.end()];
                    if matched.contains('/') && !matched.contains('+') && !matched.contains('=') {
                        continue;
                    }
                }
                line_matches.push(Match {
                    line_no,
                    byte_start: m.start(),
                    byte_end: m.end(),
                    kind: MatchKind::NamedPattern(label),
                    entropy: None,
                });
            }
        }

        // Custom patterns from config
        for re in &config.extra_patterns {
            for m in re.find_iter(line) {
                line_matches.push(Match {
                    line_no,
                    byte_start: m.start(),
                    byte_end: m.end(),
                    kind: MatchKind::CustomPattern(re.as_str().to_string()),
                    entropy: None,
                });
            }
        }

        // Entropy-based tokens (medium + high sensitivity only)
        if config.sensitivity != Sensitivity::Low {
            for (bs, be, e) in
                high_entropy_tokens(line, config.entropy_threshold, config.min_token_length)
            {
                // Deduplicate: drop if any named/custom match on this line overlaps
                let already = line_matches.iter().any(|m| {
                    m.line_no == line_no && m.byte_start < be && bs < m.byte_end
                });
                if already {
                    continue;
                }
                // Skip path-like tokens: contain '/' but no '+' or '='
                let token = &line[bs..be];
                if token.contains('/') && !token.contains('+') && !token.contains('=') {
                    continue;
                }
                line_matches.push(Match {
                    line_no,
                    byte_start: bs,
                    byte_end: be,
                    kind: MatchKind::HighEntropyToken,
                    entropy: Some(e),
                });
            }
        }

        all_matches.extend(line_matches);
    }

    all_matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Sensitivity;

    fn config(sensitivity: Sensitivity) -> ResolvedConfig {
        let (entropy_threshold, min_token_length) = match sensitivity {
            Sensitivity::Low => (f64::INFINITY, usize::MAX),
            Sensitivity::Medium => (4.5, 20),
            Sensitivity::High => (3.8, 16),
        };
        ResolvedConfig {
            sensitivity,
            extra_patterns: vec![],
            allowlist: vec![],
            entropy_threshold,
            min_token_length,
        }
    }

    #[test]
    fn detects_aws_key() {
        let text = "key: AKIAIOSFODNN7EXAMPLE";
        let matches = scan_lines(text, &config(Sensitivity::Low));
        assert!(!matches.is_empty());
        assert!(matches!(matches[0].kind, MatchKind::NamedPattern("AWS Access Key")));
    }

    #[test]
    fn allowlist_skips_line() {
        let mut cfg = config(Sensitivity::Medium);
        cfg.allowlist = vec!["example.com".to_string()];
        let text = "url: https://example.com/key=AKIAIOSFODNN7EXAMPLE";
        let matches = scan_lines(text, &cfg);
        assert!(matches.is_empty());
    }

    #[test]
    fn entropy_not_triggered_at_low() {
        let text = "token: aB3kP9mX2nQ7rS4tW6vY1zA8bC5dE0fG";
        let matches = scan_lines(text, &config(Sensitivity::Low));
        // Should not detect entropy hits at low sensitivity
        assert!(matches
            .iter()
            .all(|m| !matches!(m.kind, MatchKind::HighEntropyToken)));
    }

    fn redacted_spans<'a>(text: &'a str, sensitivity: Sensitivity) -> Vec<&'a str> {
        let line = text.lines().next().unwrap();
        scan_lines(text, &config(sensitivity))
            .iter()
            .map(|m| &line[m.byte_start..m.byte_end])
            .collect()
    }

    #[test]
    fn secret_named_key_redacts_uuid_value_in_json() {
        let text = r#"  "RAINDROP_ACCESS_TOKEN": "216b2227-25e0-4838-83e1-6a4032ca37a9","#;
        assert_eq!(
            redacted_spans(text, Sensitivity::Low),
            vec!["216b2227-25e0-4838-83e1-6a4032ca37a9"]
        );
    }

    #[test]
    fn secret_named_key_redacts_short_low_entropy_password() {
        let text = r#""CRONOMETER_PASSWORD": "Summer2024abc!""#;
        assert_eq!(redacted_spans(text, Sensitivity::Low), vec!["Summer2024abc!"]);
    }

    #[test]
    fn secret_named_key_handles_env_yaml_and_single_quotes() {
        assert_eq!(
            redacted_spans("DB_PASSWORD=hunter2hunter2", Sensitivity::Low),
            vec!["hunter2hunter2"]
        );
        assert_eq!(
            redacted_spans("client_secret: 'abc def ghi jkl'", Sensitivity::Low),
            vec!["abc def ghi jkl"]
        );
        assert_eq!(
            redacted_spans("{apiKey: abcdefgh1234}", Sensitivity::Low),
            vec!["abcdefgh1234"]
        );
    }

    #[test]
    fn secret_named_key_ignores_urls_short_values_and_other_keys() {
        for text in [
            r#""token_url": "https://auth.example.com/oauth/token""#,
            r#""max_tokens": 4096"#,
            r#""MCP_SERVER_NAME": "Trello-ToU""#,
            r#""author": "Colin Domoney""#,
        ] {
            assert!(redacted_spans(text, Sensitivity::Low).is_empty(), "{text}");
        }
    }

    #[test]
    fn file_path_not_matched_as_base64() {
        let text = "path: /Users/johndoe/Documents/Projects/myapp/src/main.rs";
        let matches = scan_lines(text, &config(Sensitivity::Medium));
        assert!(
            matches.is_empty(),
            "expected no matches for file path, got: {:?}",
            matches
        );
    }
}
