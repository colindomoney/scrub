#!/usr/bin/env python3
"""
scan_secrets.py — Pre-scrub directory scanner
Finds likely secrets in files before you feed them to an AI.
Usage: python scan_secrets.py [directory] [options]
"""

import argparse
import math
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── ANSI colours (degrades gracefully if not a tty) ──────────────────────────

def _c(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

RED    = lambda t: _c("31;1", t)
YELLOW = lambda t: _c("33;1", t)
GREEN  = lambda t: _c("32;1", t)
CYAN   = lambda t: _c("36", t)
BOLD   = lambda t: _c("1", t)
DIM    = lambda t: _c("2", t)

# ── Patterns ─────────────────────────────────────────────────────────────────

NAMED_PATTERNS = [
    ("AWS Access Key",       re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("AWS Secret Key",       re.compile(r'\b[0-9a-zA-Z/+]{40}\b')),  # loose, caught by entropy too
    ("JWT",                  re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')),
    ("PEM Block",            re.compile(r'-----BEGIN [A-Z ]+-----')),
    ("Anthropic Key",        re.compile(r'\bsk-ant-[A-Za-z0-9_-]{20,}')),
    ("OpenAI Key",           re.compile(r'\bsk-[A-Za-z0-9]{20,}')),
    ("GitHub Token",         re.compile(r'\bgh[ps]_[A-Za-z0-9]{36,}')),
    ("GitHub Fine-grained",  re.compile(r'\bgithub_pat_[A-Za-z0-9_]{80,}')),
    ("Slack Token",          re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]+')),
    ("Stripe Live Key",      re.compile(r'\bsk_live_[A-Za-z0-9]{20,}')),
    ("Stripe Test Key",      re.compile(r'\bsk_test_[A-Za-z0-9]{20,}')),
    ("Bearer Token",         re.compile(r'\bBearer\s+[A-Za-z0-9\-._~+/]{20,}')),
    ("Hex String (32+)",     re.compile(r'\b[0-9a-f]{32,}\b')),
    ("Hex String (32+ UC)",  re.compile(r'\b[0-9A-F]{32,}\b')),
    ("Private Key Header",   re.compile(r'PRIVATE KEY')),
    ("Generic API Key var",  re.compile(r'(?i)(api_?key|api_?secret|access_?token|auth_?token|secret_?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})')),
]

# File extensions to scan (add more as needed)
SCAN_EXTENSIONS = {
    '.env', '.ini', '.cfg', '.conf', '.config', '.toml', '.yaml', '.yml',
    '.json', '.properties', '.xml', '.sh', '.bash', '.zsh', '.fish',
    '.py', '.rb', '.js', '.ts', '.go', '.rs', '.java', '.php',
    '.tf', '.tfvars', '.hcl', '',  # no extension (e.g. Dockerfile)
}

# Always skip these
SKIP_DIRS = {
    '.git', 'node_modules', '.venv', 'venv', '__pycache__',
    'target', 'dist', 'build', '.terraform',
}

# Files to always skip
SKIP_FILES = {
    'package-lock.json', 'yarn.lock', 'Cargo.lock', 'poetry.lock',
}

# ── Entropy ───────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


DELIMITERS = re.compile(r'[\s,"\'=><\[\]{}()|&;#]')

def high_entropy_tokens(line: str, min_entropy: float, min_length: int) -> list[tuple[str, float]]:
    hits = []
    for token in DELIMITERS.split(line):
        token = token.strip("'\"`:=")
        if len(token) >= min_length:
            e = shannon_entropy(token)
            if e >= min_entropy:
                hits.append((token, e))
    return hits


# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    file: Path
    line_no: int
    line: str
    kind: str
    match: str
    entropy: Optional[float] = None

    def display_line(self) -> str:
        # Truncate long lines, mask the matched value
        redacted = self.line.replace(self.match, RED(f"[{self.match[:6]}…]"))
        return redacted.strip()[:120]


# ── Scanner ───────────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    sensitivity: str = "medium"   # low | medium | high
    extra_patterns: list = field(default_factory=list)
    allowlist: list = field(default_factory=list)
    max_file_size_kb: int = 512

    @property
    def entropy_threshold(self) -> float:
        return {"low": 999.0, "medium": 4.5, "high": 3.8}[self.sensitivity]

    @property
    def min_token_length(self) -> int:
        return {"low": 999, "medium": 20, "high": 16}[self.sensitivity]


def scan_file(path: Path, config: ScanConfig) -> list[Finding]:
    findings = []

    if path.stat().st_size > config.max_file_size_kb * 1024:
        return findings

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings

    for line_no, line in enumerate(text.splitlines(), 1):
        # Allowlist check
        if any(a in line for a in config.allowlist):
            continue

        # Named patterns
        for name, pattern in NAMED_PATTERNS + [(f"custom:{p}", re.compile(p)) for p in config.extra_patterns]:
            for m in pattern.finditer(line):
                findings.append(Finding(
                    file=path,
                    line_no=line_no,
                    line=line,
                    kind=name,
                    match=m.group(0),
                ))

        # Entropy
        if config.sensitivity != "low":
            for token, entropy in high_entropy_tokens(line, config.entropy_threshold, config.min_token_length):
                # Avoid double-reporting things already caught by named patterns
                already = any(f.line_no == line_no and token in f.match for f in findings)
                if not already:
                    findings.append(Finding(
                        file=path,
                        line_no=line_no,
                        line=line,
                        kind="High-entropy token",
                        match=token,
                        entropy=entropy,
                    ))

    return findings


def should_scan(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return False
    if path.suffix.lower() in SCAN_EXTENSIONS or path.name.startswith('.env'):
        return True
    return False


def scan_directory(root: Path, config: ScanConfig) -> dict[Path, list[Finding]]:
    results = {}
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if should_scan(fpath):
                findings = scan_file(fpath, config)
                if findings:
                    results[fpath] = findings
    return results


# ── Reporting ─────────────────────────────────────────────────────────────────

def report(results: dict[Path, list[Finding]], root: Path, verbose: bool = False) -> int:
    total = sum(len(v) for v in results.values())

    if not results:
        print(GREEN("✓ No secrets found."))
        return 0

    print(f"\n{RED('⚠ Secrets scan results')}\n{'─' * 60}")

    for fpath, findings in sorted(results.items()):
        rel = fpath.relative_to(root) if fpath.is_relative_to(root) else fpath
        print(f"\n{BOLD(str(rel))}  {DIM(f'({len(findings)} finding{"s" if len(findings) != 1 else ""})')}")

        for f in findings:
            entropy_str = f"  entropy={f.entropy:.2f}" if f.entropy else ""
            kind_str = YELLOW(f.kind)
            loc_str = DIM(f"line {f.line_no}")
            print(f"  {loc_str}  {kind_str}{DIM(entropy_str)}")
            if verbose:
                print(f"    {DIM('→')} {f.display_line()}")

    print(f"\n{'─' * 60}")
    print(f"{RED(f'⚠ {total} potential secret{"s" if total != 1 else ""} found')} across {len(results)} file{'s' if len(results) != 1 else ''}.\n")

    # Summary by kind
    kind_counts: dict[str, int] = defaultdict(int)
    for findings in results.values():
        for f in findings:
            kind_counts[f.kind] += 1
    print(BOLD("By type:"))
    for kind, count in sorted(kind_counts.items(), key=lambda x: -x[1]):
        print(f"  {count:3d}  {kind}")

    print()
    return total


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan a directory for secrets/tokens before pasting to AI tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", nargs="?", default=".", help="Directory or file to scan (default: cwd)")
    parser.add_argument("-s", "--sensitivity", choices=["low", "medium", "high"], default="medium",
                        help="Detection sensitivity (default: medium)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show redacted line content")
    parser.add_argument("--allowlist", nargs="*", default=[], metavar="STR",
                        help="Strings that mark a line as safe to ignore")
    parser.add_argument("--ext", nargs="*", metavar="EXT",
                        help="Additional file extensions to scan (e.g. --ext .txt .log)")
    parser.add_argument("--max-size", type=int, default=512, metavar="KB",
                        help="Skip files larger than this (default: 512 KB)")
    args = parser.parse_args()

    target = Path(args.path).resolve()
    if not target.exists():
        print(RED(f"Error: {target} does not exist"), file=sys.stderr)
        sys.exit(1)

    if args.ext:
        for e in args.ext:
            SCAN_EXTENSIONS.add(e if e.startswith('.') else f'.{e}')

    config = ScanConfig(
        sensitivity=args.sensitivity,
        allowlist=args.allowlist,
        max_file_size_kb=args.max_size,
    )

    print(f"{CYAN('scrub scanner')}  sensitivity={BOLD(args.sensitivity)}  target={CYAN(str(target))}\n")

    if target.is_file():
        findings = scan_file(target, config)
        results = {target: findings} if findings else {}
        root = target.parent
    else:
        results = scan_directory(target, config)
        root = target

    count = report(results, root, verbose=args.verbose)
    sys.exit(min(count, 255))


if __name__ == "__main__":
    main()
