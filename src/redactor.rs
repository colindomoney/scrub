use crate::scanner::Match;
use std::collections::HashMap;

fn make_placeholder(len: usize) -> String {
    match len {
        0 => String::new(),
        1 => "X".to_string(),
        2 => "[]".to_string(),
        n => format!("[{}]", "X".repeat(n - 2)),
    }
}

/// Merge a sorted list of `[start, end)` intervals into non-overlapping spans.
fn merge_intervals(mut intervals: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    if intervals.is_empty() {
        return intervals;
    }
    intervals.sort_unstable_by_key(|&(s, _)| s);
    let mut merged: Vec<(usize, usize)> = vec![intervals[0]];
    for (s, e) in intervals.into_iter().skip(1) {
        let last = merged.last_mut().unwrap();
        if s < last.1 {
            last.1 = last.1.max(e);
        } else {
            merged.push((s, e));
        }
    }
    merged
}

/// Redact matched spans in `text`, returning the sanitised string.
/// Line endings are preserved as-is.
pub fn redact(text: &str, matches: &[Match]) -> String {
    // Group byte ranges by line number (1-based)
    let mut by_line: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
    for m in matches {
        by_line
            .entry(m.line_no)
            .or_default()
            .push((m.byte_start, m.byte_end));
    }

    let mut output = String::with_capacity(text.len());

    // split_inclusive keeps the '\n' attached to its line, preserving endings.
    for (line_idx, line_with_ending) in text.split_inclusive('\n').enumerate() {
        let line_no = line_idx + 1;

        // Strip the trailing newline for processing, re-add at the end
        let (line, ending) = if let Some(trimmed) = line_with_ending.strip_suffix('\n') {
            // Handle \r\n
            let (body, cr) = if let Some(stripped) = trimmed.strip_suffix('\r') {
                (stripped, "\r\n")
            } else {
                (trimmed, "\n")
            };
            (body, cr)
        } else {
            // Last line with no trailing newline
            (line_with_ending, "")
        };

        if let Some(intervals) = by_line.get(&line_no) {
            let merged = merge_intervals(intervals.clone());
            let mut cursor = 0;
            for (start, end) in merged {
                // Clamp to line bounds (shouldn't be needed, but be safe)
                let start = start.min(line.len());
                let end = end.min(line.len());
                output.push_str(&line[cursor..start]);
                let len = end - start;
                output.push_str(&make_placeholder(len));
                cursor = end;
            }
            output.push_str(&line[cursor..]);
        } else {
            output.push_str(line);
        }

        output.push_str(ending);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_match(line_no: usize, byte_start: usize, byte_end: usize) -> Match {
        use crate::scanner::MatchKind;
        Match {
            line_no,
            byte_start,
            byte_end,
            kind: MatchKind::HighEntropyToken,
            entropy: None,
        }
    }

    #[test]
    fn placeholder_lengths() {
        assert_eq!(make_placeholder(0), "");
        assert_eq!(make_placeholder(1), "X");
        assert_eq!(make_placeholder(2), "[]");
        assert_eq!(make_placeholder(3), "[X]");
        assert_eq!(make_placeholder(10), "[XXXXXXXX]");
        assert_eq!(make_placeholder(32), "[XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX]");
    }

    #[test]
    fn placeholder_preserves_length() {
        for n in 0..=64 {
            assert_eq!(make_placeholder(n).len(), n, "failed at n={n}");
        }
    }

    #[test]
    fn redact_simple() {
        let text = "token: SECRET\n";
        // "SECRET" starts at byte 7, ends at 13
        let m = make_match(1, 7, 13);
        let result = redact(text, &[m]);
        assert_eq!(result, "token: [XXXX]\n");
        assert_eq!(result.len(), text.len());
    }

    #[test]
    fn redact_overlapping() {
        let text = "abcdef\n";
        // Two overlapping ranges: [1,4) and [3,6)  → merged [1,6)
        let m1 = make_match(1, 1, 4);
        let m2 = make_match(1, 3, 6);
        let result = redact(text, &[m1, m2]);
        // "a" + placeholder(5) + "\n"
        assert_eq!(result, "a[XXX]\n");
        assert_eq!(result.len(), text.len());
    }

    #[test]
    fn redact_multiline() {
        let text = "line1: SECRET\nline2: clean\nline3: KEY\n";
        let m1 = make_match(1, 7, 13); // SECRET (6 chars)
        let m3 = make_match(3, 7, 10); // KEY (3 chars)
        let result = redact(text, &[m1, m3]);
        assert_eq!(result, "line1: [XXXX]\nline2: clean\nline3: [X]\n");
        assert_eq!(result.len(), text.len());
    }

    #[test]
    fn redact_no_trailing_newline() {
        let text = "token: SECRET";
        let m = make_match(1, 7, 13);
        let result = redact(text, &[m]);
        assert_eq!(result, "token: [XXXX]");
    }
}
