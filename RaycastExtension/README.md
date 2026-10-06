# Scrub Clipboard

Sanitises clipboard text with the companion `scrub` Rust binary, replaces the clipboard with the clean text, then pastes it into the previously active app.

## Setup

From the repository root:

```bash
cargo install --path .
cd RaycastExtension
npm install
npm run dev
```

Raycast imports the extension while development mode is running. Assign a hotkey in Raycast Settings → Extensions → Scrub Clipboard.

Detection sensitivity (`low`, `medium` or `high`, default `high`) is set in the command's Raycast preferences and passed to `scrub --sensitivity`. Your scrub config file's `allowlist` and `extra_patterns` still apply.

The extension looks for `scrub` in `~/.cargo/bin`, `/usr/local/bin`, and `/opt/homebrew/bin`.
