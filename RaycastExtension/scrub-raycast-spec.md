# scrub — Raycast Extension Spec

## Overview

A Raycast extension that sanitises the clipboard by piping its contents through the `scrub` binary and writing the result back. Replaces the current Automator Quick Action with a native Raycast integration.

---

## Behaviour

1. User triggers the command via hotkey
2. Extension reads current clipboard contents via Raycast Clipboard API
3. Pipes contents through `/usr/local/bin/scrub --sensitivity high`
4. Writes scrubbed output back to clipboard via Raycast Clipboard API
5. Shows a brief HUD confirmation: `✓ Clipboard scrubbed (N redactions)` or `✓ Nothing to redact`
6. Optionally auto-pastes into the active window

---

## Implementation

- **Type**: Raycast Extension, single command, no UI
- **Language**: TypeScript
- **Scaffold**: `create-raycast-extension`

### Command

```typescript
import { Clipboard, showHUD } from "@raycast/api";
import { execSync } from "child_process";

export default async function Command() {
  const text = await Clipboard.readText();
  if (!text) {
    await showHUD("⚠ Clipboard is empty");
    return;
  }

  const scrubbed = execSync(
    `/usr/local/bin/scrub --sensitivity high`,
    { input: text, encoding: "utf8" }
  );

  await Clipboard.copy(scrubbed);
  
  // Count redactions by comparing [XXXX] blocks
  const count = (scrubbed.match(/\[X+\]/g) || []).length;
  await showHUD(count > 0 ? `✓ ${count} secret${count > 1 ? "s" : ""} redacted` : `✓ Nothing to redact`);
}
```

---

## Package Manifest (`package.json`)

```json
{
  "name": "scrub-clipboard",
  "title": "Scrub Clipboard",
  "description": "Sanitise clipboard contents before pasting into AI tools",
  "icon": "icon.png",
  "author": "colind",
  "categories": ["Security"],
  "license": "MIT",
  "commands": [
    {
      "name": "scrub-clipboard",
      "title": "Scrub Clipboard",
      "description": "Strip secrets and tokens from clipboard",
      "mode": "no-view"
    }
  ],
  "dependencies": {
    "@raycast/api": "^1.0.0"
  }
}
```

---

## Notes

- `no-view` mode = no UI, runs silently in background
- `execSync` with `input:` option pipes text to scrub's stdin cleanly — no shell escaping issues
- HUD message disappears automatically after ~2 seconds
- Assign hotkey in Raycast Settings → Extensions → Scrub Clipboard
- Prereq: `/usr/local/bin/scrub` must exist (or update path to `~/.cargo/bin/scrub`)

---

## Optional Enhancement

Auto-paste after scrubbing — add after `Clipboard.copy()`:

```typescript
import { pasteText } from "@raycast/api";
await pasteText(scrubbed);
```

This replaces the `osascript keystroke` hack in the Automator version.
