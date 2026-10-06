# scrub

Redacts secrets and tokens from text. Designed for piping into AI tools, Pastebot transformations, and CI gates.

```
❯ echo "ADMIN_KEY=SNhvsAZx4CROefoOs8Pl+qlHu62BZwgrkHLZ2EtXix7ihAAn" | scrub
ADMIN_KEY=[XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX]
```

Replacement strings are length-matched to the original — your diffs and formatting stay intact.

---

## Install

```bash
cargo install --path .
```

Or build the binary directly:

```bash
cargo build --release
# binary at ./target/release/scrub
```

---

## Usage

```
scrub [OPTIONS] [INPUT_FILE]

Options:
  -s, --sensitivity <level>   low | medium | high  [default: medium]
  -o, --output <file>         Write to file instead of stdout
  -c, --config <file>         Config file  [default: ~/.config/scrub/config.toml]
  -v, --verbose               Print redaction summary to stderr
      --dry-run               Show what would be redacted without modifying output
      --check                 Exit 0 if clean, exit N (count) if secrets found
  -h, --help
  -V, --version
```

### Pipe from stdin

```bash
cat .env | scrub
cat .env | scrub -s high
```

### File in, file out

```bash
scrub secrets.txt -o clean.txt
```

### Check mode (for CI / git hooks)

```bash
scrub --check .env
echo $?   # 0 = clean, N = number of secrets found
```

```bash
# Pre-commit hook
scrub --check --verbose .env || exit 1
```

### Directory sweep

```bash
find . -name ".env*" -exec scrub --check {} \;
```

---

## Sensitivity levels

| Level | What it catches |
|---|---|
| `low` | Named patterns only (AWS keys, JWTs, API key prefixes, etc.) |
| `medium` | Named patterns + tokens with Shannon entropy > 4.5 and length > 20 |
| `high` | Named patterns + entropy > 3.8 and length > 16 |

Default is `medium`. Use `high` when you want maximum coverage at the cost of more false positives.

---

## Named patterns

Detected at all sensitivity levels:

- AWS access keys (`AKIA...`)
- JWTs (`eyJ...`)
- PEM blocks / private key headers
- Anthropic, OpenAI, GitHub, Slack, Stripe API keys
- Bearer tokens
- Hex strings ≥ 32 chars
- Base64 blobs ≥ 40 chars
- Values ≥ 8 chars assigned to any key whose name contains `token`, `secret`, `password`/`passwd`, `api_key`/`apikey` or `private_key`, in JSON, YAML, TOML or env form (`"RAINDROP_ACCESS_TOKEN": "…"`, `DB_PASSWORD=…`). Only the value is redacted; URL values are left alone.

---

## Config file

Optional `~/.config/scrub/config.toml`:

```toml
sensitivity = "high"

extra_patterns = [
  "mycompany-[a-z0-9]{20}",
]

allowlist = [
  "example.com",
]
```

`allowlist` entries cause the entire line to be skipped.

---

## Pastebot

Set the transformation command to:

```
scrub --sensitivity high
```

Stdin in, stdout out.

---

## scan_secrets.py

Companion script for auditing directories before scrubbing. Reports findings without modifying anything.

```bash
# Scan all .env files in a project
find ~/projects/myapp -name ".env*" -exec python3 scan_secrets.py {} \;

# Scan a whole directory
python3 scan_secrets.py ~/projects/myapp -s high -v
```
