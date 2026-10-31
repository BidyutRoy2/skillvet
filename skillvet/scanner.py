"""Core scanning engine for skillvet.

Scans agent skill files (SKILL.md), MCP server configs, shell scripts and
helper code for patterns that are dangerous when an AI agent executes them:
remote code execution, credential theft, destructive commands, prompt
injection and data exfiltration.

No third-party dependencies. Python 3.9+.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5}

# (rule_id, severity, pattern, title, recommendation)
RULES = [
    (
        "SV001", "critical",
        re.compile(r"(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh)", re.I),
        "Remote code piped straight into a shell",
        "Download the script, pin it to a version/commit, verify a checksum, then run it.",
    ),
    (
        "SV002", "critical",
        re.compile(r"(os\.environ|process\.env|\$env:|\benviron\b)[^\n]{0,80}(requests\.post|fetch\(|curl|wget|http)", re.I),
        "Environment variables appear to be sent over the network",
        "Never transmit environment variables. Pass only the single credential a task needs, scoped and short-lived.",
    ),
    (
        "SV003", "critical",
        re.compile(r"(\.ssh/id_|\.aws/credentials|\.env\b|/etc/passwd|keychain|credential manager)", re.I),
        "Reads credential / secret storage locations",
        "A skill should never read SSH keys, cloud credentials or .env files. Declare needed secrets explicitly instead.",
    ),
    (
        "SV004", "high",
        re.compile(r"\brm\s+-(rf|fr|r\s+-f|f\s+-r)\b[^\n]*(\s/($|\s)|~|\$HOME|\*)", re.I),
        "Recursive force-delete aimed at root, home or wildcard paths",
        "Scope deletions to a named working directory and require explicit confirmation.",
    ),
    (
        "SV005", "high",
        re.compile(r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)", re.I),
        "Prompt-injection phrasing: tries to override prior instructions",
        "Remove instruction-override language. A skill must never ask the agent to ignore its system or user instructions.",
    ),
    (
        "SV006", "high",
        re.compile(r"(do not|don't|never)\s+(tell|inform|mention to|reveal to)\s+(the\s+)?user", re.I),
        "Instruction to hide actions from the user",
        "Agents must stay transparent. Delete any instruction that conceals behaviour from the user.",
    ),
    (
        "SV007", "high",
        re.compile(r"(base64\s+(-d|--decode|-D)|atob\(|FromBase64String|certutil\s+-decode)", re.I),
        "Decodes opaque base64 payloads (common malware staging)",
        "Ship readable code. If a payload must be decoded, document exactly what it is and verify its hash.",
    ),
    (
        "SV008", "medium",
        re.compile(r"\b(eval\(|exec\(|os\.system\(|subprocess\.(call|run|Popen)\([^\n]*shell\s*=\s*True)", re.I),
        "Dynamic code execution (eval / exec / shell=True)",
        "Replace dynamic execution with explicit, reviewable function calls and argument lists.",
    ),
    (
        "SV009", "medium",
        re.compile(r"(pip\s+install|npm\s+install|npx)\s+[^\n]*(git\+https|https?://[^\s]+\.(tar\.gz|tgz|zip|whl))", re.I),
        "Installs packages from an unpinned remote URL",
        "Install from the official registry with a pinned version and a lockfile.",
    ),
    (
        "SV010", "medium",
        re.compile(r"(webhook\.site|requestbin|ngrok\.io|trycloudflare|burpcollaborator|oastify)", re.I),
        "References a known data-exfiltration / request-capture endpoint",
        "Remove test-capture endpoints. Network calls should go only to the service the skill is for.",
    ),
    (
        "SV011", "medium",
        re.compile(r"(chmod\s+777|chmod\s+\+x\s+/|icacls\s+[^\n]*/grant\s+everyone|Set-ExecutionPolicy\s+(Unrestricted|Bypass))", re.I),
        "Weakens system permissions or execution policy",
        "Use least-privilege permissions and never disable the platform execution policy.",
    ),
    (
        "SV012", "low",
        re.compile(r"\b(sudo|runas|Start-Process\s+[^\n]*-Verb\s+RunAs)\b", re.I),
        "Requests elevated privileges",
        "Document why elevation is required and limit it to the smallest possible step.",
    ),
    (
        "SV013", "low",
        re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?/", re.I),
        "Hard-coded raw IP address endpoint",
        "Use a named, verifiable domain over HTTPS so users can audit where data goes.",
    ),
    (
        "SV014", "medium",
        re.compile(r"(send|post|upload|transmit)[^\n]{0,60}(conversation|chat history|clipboard|browser history|cookies)", re.I),
        "May exfiltrate conversation, clipboard or browser data",
        "A skill must not collect or transmit the user's conversations, clipboard, cookies or history.",
    ),
]

SCAN_EXTENSIONS = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".ts", ".mjs"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
MAX_FILE_BYTES = 2_000_000


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    snippet: str
    recommendation: str


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: list = field(default_factory=list)

    @property
    def score(self) -> int:
        penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 55:
            return "C"
        if s >= 35:
            return "D"
        return "F"

    @property
    def verdict(self) -> str:
        if any(f.severity == "critical" for f in self.findings):
            return "DO NOT INSTALL without a full manual review"
        if any(f.severity == "high" for f in self.findings):
            return "Review carefully before installing"
        if self.findings:
            return "Mostly safe — check the findings below"
        return "No known dangerous patterns found"

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "score": self.score,
            "grade": self.grade,
            "verdict": self.verdict,
            "findings": [asdict(f) for f in self.findings],
        }


def iter_target_files(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.suffix.lower() in SCAN_EXTENSIONS:
                yield p


def scan_path(root) -> ScanResult:
    root = Path(root)
    result = ScanResult(root=str(root))
    for path in iter_target_files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        result.files_scanned += 1
        try:
            rel = str(path.relative_to(root)) if root.is_dir() else path.name
        except ValueError:
            rel = str(path)
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule_id, severity, pattern, title, rec in RULES:
                if pattern.search(line):
                    result.findings.append(Finding(
                        rule_id=rule_id, severity=severity, title=title,
                        file=rel, line=lineno,
                        snippet=line.strip()[:160], recommendation=rec,
                    ))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result.findings.sort(key=lambda f: (order.get(f.severity, 9), f.file, f.line))
    return result


def render_text(result: ScanResult) -> str:
    lines = []
    lines.append(f"skillvet scan: {result.root}")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Trust score: {result.score}/100  (grade {result.grade})")
    lines.append(f"Verdict: {result.verdict}")
    lines.append("")
    if not result.findings:
        lines.append("No findings. Nothing matched the known dangerous patterns.")
    for f in result.findings:
        lines.append(f"[{f.severity.upper()}] {f.rule_id} {f.title}")
        lines.append(f"  at {f.file}:{f.line}")
        lines.append(f"  > {f.snippet}")
        lines.append(f"  fix: {f.recommendation}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(result: ScanResult) -> str:
    lines = []
    lines.append("## skillvet trust report")
    lines.append("")
    lines.append(f"- **Target:** `{result.root}`")
    lines.append(f"- **Files scanned:** {result.files_scanned}")
    lines.append(f"- **Trust score:** {result.score}/100 (grade **{result.grade}**)")
    lines.append(f"- **Verdict:** {result.verdict}")
    lines.append("")
    if result.findings:
        lines.append("| Severity | Rule | Finding | Location |")
        lines.append("|---|---|---|---|")
        for f in result.findings:
            lines.append(f"| {f.severity} | {f.rule_id} | {f.title} | `{f.file}:{f.line}` |")
        lines.append("")
        for f in result.findings:
            lines.append(f"### {f.rule_id} — {f.title}")
            lines.append(f"> {f.snippet}")
            lines.append(f"**Fix:** {f.recommendation}")
            lines.append("")
    else:
        lines.append("No findings. Nothing matched the known dangerous patterns.")
    return "\n".join(lines).rstrip() + "\n"


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2) + "\n"
