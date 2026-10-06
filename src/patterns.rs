use regex::Regex;
use std::sync::LazyLock;

macro_rules! pat {
    ($re:expr) => {
        LazyLock::new(|| Regex::new($re).expect("invalid built-in pattern"))
    };
}

static AWS_ACCESS_KEY: LazyLock<Regex> = pat!(r"\bAKIA[0-9A-Z]{16}\b");
static AWS_SECRET_KEY: LazyLock<Regex> = pat!(r"\b[0-9a-zA-Z/+]{40}\b");
static JWT: LazyLock<Regex> =
    pat!(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+");
static PEM_BLOCK: LazyLock<Regex> = pat!(r"-----BEGIN [A-Z ]+-+");
static ANTHROPIC_KEY: LazyLock<Regex> = pat!(r"\bsk-ant-[A-Za-z0-9_-]{20,}");
static OPENAI_KEY: LazyLock<Regex> = pat!(r"\bsk-[A-Za-z0-9]{20,}");
static GITHUB_TOKEN: LazyLock<Regex> = pat!(r"\bgh[ps]_[A-Za-z0-9]{36,}");
static GITHUB_FINE_GRAINED: LazyLock<Regex> = pat!(r"\bgithub_pat_[A-Za-z0-9_]{80,}");
static SLACK_TOKEN: LazyLock<Regex> = pat!(r"\bxox[baprs]-[A-Za-z0-9\-]+");
static STRIPE_LIVE: LazyLock<Regex> = pat!(r"\bsk_live_[A-Za-z0-9]{20,}");
static STRIPE_TEST: LazyLock<Regex> = pat!(r"\bsk_test_[A-Za-z0-9]{20,}");
static BEARER_TOKEN: LazyLock<Regex> =
    pat!(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}");
static HEX_LOWER: LazyLock<Regex> = pat!(r"\b[0-9a-f]{32,}\b");
static HEX_UPPER: LazyLock<Regex> = pat!(r"\b[0-9A-F]{32,}\b");
static PRIVATE_KEY_HEADER: LazyLock<Regex> = pat!(r"PRIVATE KEY");
// Value assigned to a secret-sounding key, in JSON, YAML, TOML or env form:
// `"RAINDROP_ACCESS_TOKEN": "…"`, `DB_PASSWORD=…`, `client_secret: '…'`.
// Only the value is redacted: the scanner uses the first capture group that
// participates (double-quoted, single-quoted or bare), not the whole match.
static SECRET_KEY_VALUE: LazyLock<Regex> = pat!(
    r#"(?i)\b[A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|api_?key|private_?key)[A-Za-z0-9_.-]*["']?\s*[:=]\s*(?:"([^"]{8,})"|'([^']{8,})'|([^\s"'`,;})\]]{8,}))"#
);
static BASE64_BLOB: LazyLock<Regex> = pat!(r"[A-Za-z0-9+/]{40,}={0,2}");

static PATTERNS: [(&str, &LazyLock<Regex>); 17] = [
    ("AWS Access Key",      &AWS_ACCESS_KEY),
    ("Anthropic Key",       &ANTHROPIC_KEY),
    ("OpenAI Key",          &OPENAI_KEY),
    ("GitHub Token",        &GITHUB_TOKEN),
    ("GitHub Fine-grained", &GITHUB_FINE_GRAINED),
    ("Slack Token",         &SLACK_TOKEN),
    ("Stripe Live Key",     &STRIPE_LIVE),
    ("Stripe Test Key",     &STRIPE_TEST),
    ("Bearer Token",        &BEARER_TOKEN),
    ("JWT",                 &JWT),
    ("PEM Block",           &PEM_BLOCK),
    ("Private Key Header",  &PRIVATE_KEY_HEADER),
    ("Secret-named key",    &SECRET_KEY_VALUE),
    ("Hex String 32+",      &HEX_LOWER),
    ("Hex String 32+ UC",   &HEX_UPPER),
    ("AWS Secret Key",      &AWS_SECRET_KEY),
    ("Base64 Blob 40+",     &BASE64_BLOB),
];

/// Returns all built-in named patterns, more-specific first.
pub fn named_patterns() -> &'static [(&'static str, &'static LazyLock<Regex>)] {
    &PATTERNS
}
