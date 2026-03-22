use crate::scanner::{Match, MatchKind};

pub fn print_verbose_summary(matches: &[Match]) {
    let total = matches.len();
    if total == 0 {
        eprintln!("[scrub] 0 redactions made.");
        return;
    }
    eprintln!("[scrub] {total} redaction{}:", if total == 1 { "" } else { "s" });
    for m in matches {
        let entropy_str = m
            .entropy
            .map(|e| format!(" (entropy {e:.1})"))
            .unwrap_or_default();
        let kind_str = match &m.kind {
            MatchKind::NamedPattern(label) => format!("Matched pattern: {label}"),
            MatchKind::CustomPattern(pat) => format!("Matched custom pattern: {pat}"),
            MatchKind::HighEntropyToken => {
                let len = m.matched_len();
                format!("High-entropy token{entropy_str} (len {len})")
            }
        };
        let entropy_suffix = match &m.kind {
            MatchKind::HighEntropyToken => String::new(), // already included above
            _ => entropy_str,
        };
        eprintln!("  line {}:  {kind_str}{entropy_suffix}", m.line_no);
    }
}

pub fn print_dry_run_summary(matches: &[Match]) {
    let total = matches.len();
    if total == 0 {
        eprintln!("[scrub] dry-run: nothing to redact.");
        return;
    }
    eprintln!("[scrub] dry-run: {total} would be redacted:");
    for m in matches {
        let entropy_str = m
            .entropy
            .map(|e| format!(" (entropy {e:.1})"))
            .unwrap_or_default();
        let kind_str = match &m.kind {
            MatchKind::NamedPattern(label) => label.to_string(),
            MatchKind::CustomPattern(pat) => format!("custom: {pat}"),
            MatchKind::HighEntropyToken => {
                format!("High-entropy token{entropy_str}, len {}", m.matched_len())
            }
        };
        let entropy_suffix = match &m.kind {
            MatchKind::HighEntropyToken => String::new(),
            _ => entropy_str,
        };
        eprintln!("  line {}:  {kind_str}{entropy_suffix}", m.line_no);
    }
}
