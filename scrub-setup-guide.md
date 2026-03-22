# scrub — Setup Guide

## Overview

A clipboard sanitiser that strips secrets, API keys, and tokens before you paste them into AI tools. Built from:

- **`scrub`** — Rust CLI that does the actual redaction
- **`scan_secrets.py`** — Python scanner for auditing directories
- **Automator Quick Action** — macOS hotkey integration

---

## 1. Build and Install `scrub`

```bash
# Clone/create the project and build
cargo build --release

# Install globally via Cargo
cargo install --path .

# Or copy manually
sudo cp target/release/scrub /usr/local/bin/scrub

# Remove quarantine flag (required on macOS)
sudo xattr -rd com.apple.quarantine /usr/local/bin/scrub
```

Verify:
```bash
echo "API_KEY=sk-ant-abc123def456" | scrub --sensitivity high
```

---

## 2. Automator Quick Action

This is the hotkey integration that sanitises and auto-pastes your clipboard.

1. Open **Automator** → **New Document** → **Quick Action**
2. Set **Workflow receives** → `no input` in `any application`
3. Add a **Run Shell Script** action
4. Set **Shell** to `/bin/zsh`, **Pass input** to `to stdin`
5. Paste this script:

```bash
cleaned=$(osascript -e 'get the clipboard' | tr '\r' '\n' | /usr/local/bin/scrub --sensitivity high)
echo "$cleaned" | pbcopy
osascript -e 'tell application "System Events" to keystroke "v" using command down'
```

6. **⌘S** → Save as `Scrub Clipboard`

### Assign a Hotkey

**System Settings → Keyboard → Keyboard Shortcuts → Services → General** → find **Scrub Clipboard** → assign your hotkey.

---

## 3. Usage

1. Copy text containing secrets as normal
2. Hit your hotkey instead of ⌘V
3. scrub sanitises the clipboard and auto-pastes the clean version

Secrets are replaced with length-matched `[XXXXXX]` blocks so the AI can see the structure of what you're sharing without the actual values.

---

## 4. Sensitivity Levels

| Level | Behaviour |
|---|---|
| `low` | Named patterns only (AWS keys, JWTs, known prefixes) |
| `medium` | Named patterns + high entropy tokens (default) |
| `high` | Aggressive — nukes anything suspicious |

The Automator action runs at `--sensitivity high`. Edit the script to change this.

---

## 5. Directory Scanner

Use `scan_secrets.py` to audit a directory before sharing or committing:

```bash
# Scan current directory
python scan_secrets.py

# Scan specific directory with verbose output
python scan_secrets.py ~/projects/myapp --sensitivity high --verbose

# Exit code = number of secrets found (0 = clean)
python scan_secrets.py . && echo "clean"

# Scan a single file
python scan_secrets.py .env --verbose
```

Useful for:
- Pre-commit audits
- Checking a working directory before sharing with AI tools
- CI pipeline gates

---

## 6. Pastebot

Pastebot is **App Store sandboxed** and cannot execute external binaries. It cannot be used for this integration.

---

## 7. Files

| File | Purpose |
|---|---|
| `scrub` | Rust binary — the redaction engine |
| `scrub-spec.md` | Full feature specification |
| `scan_secrets.py` | Directory/file secret scanner |
| `~/Library/Services/Scrub Clipboard.workflow` | Automator Quick Action |
