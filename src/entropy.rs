use std::collections::HashMap;

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for b in s.bytes() {
        *freq.entry(b).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    -freq
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Split `line` on delimiter characters, strip quote/assignment chars from token
/// edges, and return `(byte_start, byte_end, entropy)` for tokens meeting the
/// length and entropy thresholds. Byte offsets are relative to `line`.
pub fn high_entropy_tokens(
    line: &str,
    threshold: f64,
    min_len: usize,
) -> Vec<(usize, usize, f64)> {
    let mut results = Vec::new();

    // Split on delimiters (same set as Python reference)
    let mut start = 0;
    let mut in_segment = false;
    let mut seg_start = 0;

    let is_delim = |b: u8| {
        matches!(
            b,
            b' ' | b'\t' | b'\n' | b'\r' | b','  | b'"' | b'\'' | b'='  |
            b'>'  | b'<'  | b'['  | b']'  | b'{'  | b'}'  | b'('  | b')'  |
            b'|'  | b'&'  | b';'  | b'#'
        )
    };

    let bytes = line.as_bytes();
    let mut i = 0;
    while i <= bytes.len() {
        let at_delim = i == bytes.len() || is_delim(bytes[i]);
        if at_delim {
            if in_segment {
                let raw_token = &line[seg_start..i];
                // Strip leading/trailing characters as Python does: `'\"` `:=`
                let stripped = raw_token.trim_matches(|c| matches!(c, '\'' | '"' | '`' | ':' | '='));
                if stripped.len() >= min_len {
                    let e = shannon_entropy(stripped);
                    if e > threshold {
                        // Locate stripped token within the original line segment
                        // to get correct byte offsets.
                        if let Some(offset) = line[seg_start..i].find(stripped) {
                            let bs = seg_start + offset;
                            let be = bs + stripped.len();
                            results.push((bs, be, e));
                        }
                    }
                }
                in_segment = false;
            }
            start = i + 1;
        } else if !in_segment {
            seg_start = i;
            in_segment = true;
        }
        i += 1;
    }
    let _ = start; // suppress unused warning

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_uniform() {
        // "abcd" has entropy 2.0 (4 equally likely symbols)
        let e = shannon_entropy("abcd");
        assert!((e - 2.0).abs() < 1e-9, "got {e}");
    }

    #[test]
    fn entropy_single_char() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn high_entropy_found() {
        let line = "token=aB3kP9mX2nQ7rS4tW6vY1zA8bC5dE0fG";
        let hits = high_entropy_tokens(line, 4.5, 20);
        assert!(!hits.is_empty(), "expected entropy hit");
        let (bs, be, _) = hits[0];
        assert_eq!(&line[bs..be], "aB3kP9mX2nQ7rS4tW6vY1zA8bC5dE0fG");
    }

    #[test]
    fn low_entropy_not_found() {
        let line = "token=aaaaaaaaaaaaaaaaaaaaaa";
        let hits = high_entropy_tokens(line, 4.5, 20);
        assert!(hits.is_empty());
    }
}
