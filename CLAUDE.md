# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`scrub` is a secret sanitizer — it reads text, redacts secrets/tokens, and outputs clean text. It's designed to work as a standalone CLI and as a Pastebot transformation.

The repo currently contains:
- `scan_secrets.py` — a working Python pre-scrub directory scanner (standalone utility)
- `scrub-spec.md` — the full spec for the main `scrub` Rust CLI (not yet implemented)

## scan_secrets.py

Pre-scrub scanner that finds likely secrets in files before feeding them to an AI.

```bash
# Scan current directory
python scan_secrets.py

# Scan a specific path with high sensitivity and verbose output
python scan_secrets.py /path/to/dir -s high -v

# Scan a single file
python scan_secrets.py somefile.env

# Add extra extensions and allowlist strings
python scan_secrets.py --ext .txt .log --allowlist "example.com"
```

Exit code = number of findings (capped at 255). Exit 0 = clean.

## Planned Rust CLI (`scrub`)

Per `scrub-spec.md`, the main tool is a Rust binary using:
- `clap` — CLI argument parsing
- `regex` — named pattern matching
- `serde` / `toml` — config file (`~/.config/scrub/config.toml`)
- `dirs` — config path resolution

### Key design decisions from the spec

**Replacement format**: `[XXXXXX]` — length-matched to the redacted string (total length including brackets = original length).

**Sensitivity levels** (`--sensitivity low|medium|high`, default `medium`):
- `low`: named patterns only
- `medium`: named patterns + entropy > 4.5 AND length > 20
- `high`: named patterns + entropy > 3.8 AND length > 16

**Named patterns** (all levels): AWS keys, JWTs, PEM blocks, `sk-`/`sk-ant-`/`ghp_`/`ghs_`/`xox*-`/Stripe/Bearer prefixes, hex ≥ 32 chars, base64 ≥ 40 chars.

**Check mode** (`--check`): no stdout, exits with count of secrets found (0 = clean). Designed for git pre-commit hooks and CI.

**Config file** supports `sensitivity`, `extra_patterns` (regex list), and `allowlist` (strings that mark a line safe).
