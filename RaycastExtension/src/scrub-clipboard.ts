import { Clipboard, showHUD } from "@raycast/api";
import { execFileSync } from "child_process";
import { existsSync } from "fs";
import { homedir } from "os";

function findScrub(): string {
  const candidates = [
    `${homedir()}/.cargo/bin/scrub`,
    "/usr/local/bin/scrub",
    "/opt/homebrew/bin/scrub",
  ];
  const found = candidates.find(existsSync);
  if (!found) throw new Error("scrub binary not found");
  return found;
}

export default async function Command() {
  const text = await Clipboard.readText();
  if (!text) {
    await showHUD("⚠ Clipboard is empty");
    return;
  }

  let scrubBin: string;
  try {
    scrubBin = findScrub();
  } catch {
    await showHUD(
      "⚠ scrub not installed — run: cargo install --path <scrub-repo>",
    );
    return;
  }

  let scrubbed: string;
  try {
    scrubbed = execFileSync(scrubBin, ["--sensitivity", "high"], {
      input: text,
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch {
    await showHUD("⚠ scrub failed");
    return;
  }

  await Clipboard.copy(scrubbed);
  await Clipboard.paste(scrubbed);

  const count = (scrubbed.match(/\[X+\]/g) || []).length;
  await showHUD(
    count > 0
      ? `✓ ${count} secret${count > 1 ? "s" : ""} redacted`
      : `✓ Nothing to redact`,
  );
}
