# `scrub` — Secret Sanitiser Spec

## Overview
CLI tool that reads text, redacts secrets/tokens, outputs clean text. Designed to work standalone and as a Pastebot transformation.

---

## I/O

- **Input**: stdin (default) or `--input <file>`
- **Output**: stdout (default) or `--output <file>`
- **Replacement**: `[XXXXXX]` — length-matched to the redacted string. The replacement string is wrapped in `[` and `]` with the interior filled with `X` characters so the total length matches the original. e.g. a 10-char token → `[XXXXXXXX]`, a 32-char token → `[XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX]`

---

## Sensitivity Levels

`--sensitivity <low|medium|high>` (default: `medium`)

| Level | Behaviour |
|---|---|
| `low` | Named patterns only (AWS, JWT, API key prefixes etc) |
| `medium` | Named patterns + high entropy tokens |
| `high` | Named patterns + aggressive entropy — nukes anything suspicious |

---

## Detection

**Named patterns (all levels)**
- AWS keys: `AKIA[0-9A-Z]{16}`
- JWTs: `eyJ…` three-part dot structure
- PEM blocks
- Known prefixes: `sk-`, `sk-ant-`, `ghp_`, `ghs_`, `xox[baprs]-`, `stripe sk_live_/sk_test_`, `Bearer <token>`
- Hex strings ≥ 32 chars
- Base64 blobs ≥ 40 chars

**Entropy (medium + high)**
- Tokenise on whitespace + common delimiters (`,`, `"`, `'`, `=`, `:`)
- Calculate Shannon entropy per token
- Medium: entropy > 4.5 AND length > 20
- High: entropy > 3.8 AND length > 16

---

## Config File

Optional `~/.config/scrub/config.toml`:

```toml
sensitivity = "high"

# Extra patterns (regex)
extra_patterns = [
  "mycompany-[a-z0-9]{20}",
]

# Tokens/strings to always ignore (allowlist)
allowlist = [
  "example.com",
]
```

---

## CLI

```
scrub [OPTIONS] [INPUT_FILE]

Options:
  -s, --sensitivity <level>   low | medium | high [default: medium]
  -o, --output <file>         Write to file instead of stdout
  -c, --config <file>         Config file [default: ~/.config/scrub/config.toml]
  -v, --verbose               Print redaction summary to stderr
      --dry-run               Show what would be redacted without modifying
      --check                 Check mode: no output, exit 0 if clean, exit N (count) if secrets found
  -h, --help
  -V, --version
```

---

## Check Mode

`--check` flag: scan only, no stdout output.

- **Exit 0**: no secrets found
- **Exit N**: N secrets found (capped at 255 for shell compatibility)
- Prints findings to stderr when combined with `--verbose`

Intended for:
- Directory sweeps: `find . -name "*.env" -exec scrub --check {} \;`
- Git pre-commit hooks: fail the commit if secrets detected
- CI pipeline gates

---

## Verbose output (stderr)

```
[scrub] 4 redactions made:
  line 3:  JWT token (entropy 5.2)
  line 7:  Matched pattern: aws_key
  line 12: High-entropy token (entropy 4.8, len 34)
  line 12: Matched pattern: sk- prefix
```

---

## Pastebot wiring
Transformation shell command:
```bash
scrub --sensitivity high
```
Stdin in, stdout out — done.

---

## Crates
- `clap` — CLI
- `regex` — patterns
- `serde` / `toml` — config
- `dirs` — config path resolution
