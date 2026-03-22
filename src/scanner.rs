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
            for m in re.find_iter(line) {
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
                if !already {
                    line_matches.push(Match {
                        line_no,
                        byte_start: bs,
                        byte_end: be,
                        kind: MatchKind::HighEntropyToken,
                        entropy: Some(e),
                    });
                }
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
}
