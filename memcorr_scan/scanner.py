"""
Core scan engine for memcorr-scan.

Two detection layers:
1. Pattern rules (rules.py) — single-line regex matches for known-dangerous calls.
2. A lightweight per-function heuristic for use-after-free and double-free: split each
   function body into statements, track `free(ptr)` calls, and flag any later statement
   in the same function that references the same pointer name without an intervening
   reassignment (`ptr = ...`) or a clear guard (`if (ptr)` / `ptr = NULL`).

This is deliberately NOT a full dataflow/alias analysis (no real C compiler frontend is
used) — see README "Limitations" for what that means in practice and what a v2 built on
libclang's AST would add.
"""

import re
from dataclasses import dataclass, field

from .rules import RULES


COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')
FUNC_SIG_RE = re.compile(
    r"^[\w\*\s]+?\b(\w+)\s*\([^;{]*\)\s*\{", re.MULTILINE
)
FREE_CALL_RE = re.compile(r"\bfree\s*\(\s*(\w+)\s*\)")
REASSIGN_RE_TMPL = r"\b{name}\s*=\s*(?!{name}\b)"
GUARD_RE_TMPL = r"\b(if|while)\s*\(\s*!?\s*{name}\b"


@dataclass
class Finding:
    rule_id: str
    title: str
    cwe: str
    severity: str
    file: str
    line: int
    snippet: str
    description: str
    recommendation: str


@dataclass
class ScanResult:
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)

    def by_severity(self) -> dict:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def _strip_for_matching(src: str) -> str:
    """Blank out comments and string literals (preserving line numbers/length) so rule
    regexes don't false-positive on dangerous-looking text inside a comment or string."""
    def blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    src = COMMENT_RE.sub(blank, src)
    src = STRING_RE.sub(blank, src)
    return src


def _line_of(src: str, offset: int) -> int:
    return src.count("\n", 0, offset) + 1


def _snippet(lines: list[str], line_no: int) -> str:
    idx = line_no - 1
    return lines[idx].strip() if 0 <= idx < len(lines) else ""


def _scan_pattern_rules(path: str, raw_src: str) -> list[Finding]:
    clean = _strip_for_matching(raw_src)
    lines = raw_src.splitlines()
    findings = []
    for rule in RULES:
        for m in rule.pattern.finditer(clean):
            line_no = _line_of(raw_src, m.start())
            findings.append(Finding(
                rule_id=rule.id, title=rule.title, cwe=rule.cwe,
                severity=rule.severity, file=path, line=line_no,
                snippet=_snippet(lines, line_no),
                description=rule.description, recommendation=rule.recommendation,
            ))
    return findings


def _extract_functions(clean_src: str) -> list[tuple[str, int, str]]:
    """Return (name, start_offset_of_body, body_text) for each top-level function found
    via brace matching from the opening '{'."""
    out = []
    for m in FUNC_SIG_RE.finditer(clean_src):
        name = m.group(1)
        if name in ("if", "for", "while", "switch", "return"):
            continue
        start = m.end() - 1  # position of '{'
        depth = 0
        i = start
        while i < len(clean_src):
            if clean_src[i] == "{":
                depth += 1
            elif clean_src[i] == "}":
                depth -= 1
                if depth == 0:
                    body = clean_src[start:i + 1]
                    out.append((name, start, body))
                    break
            i += 1
    return out


def _scan_use_after_free(path: str, raw_src: str) -> list[Finding]:
    clean = _strip_for_matching(raw_src)
    lines = raw_src.splitlines()
    findings = []
    for fname, body_start, body in _extract_functions(clean):
        freed = {}  # name -> offset within file where free() happened
        seen_double_free = set()
        for m in re.finditer(r"[^;{}]+[;{}]", body):
            stmt = m.group(0)
            leading_ws = len(stmt) - len(stmt.lstrip())
            stmt_abs_start = body_start + m.start() + leading_ws

            free_m = FREE_CALL_RE.search(stmt)
            if free_m:
                name = free_m.group(1)
                if name in freed and name not in seen_double_free:
                    line_no = _line_of(raw_src, stmt_abs_start)
                    findings.append(Finding(
                        rule_id="DOUBLE_FREE", title=f"Possible double free of '{name}'",
                        cwe="CWE-415", severity="high", file=path, line=line_no,
                        snippet=_snippet(lines, line_no),
                        description=f"'{name}' appears to be passed to free() twice in "
                                    f"function '{fname}' with no reassignment in between.",
                        recommendation=f"Set {name} = NULL immediately after freeing it, "
                                        f"and/or guard the second free with an if ({name}) check.",
                    ))
                    seen_double_free.add(name)
                freed[name] = stmt_abs_start
                continue

            for name in list(freed.keys()):
                if re.search(REASSIGN_RE_TMPL.format(name=re.escape(name)), stmt):
                    del freed[name]
                    seen_double_free.discard(name)
                    continue
                if re.search(GUARD_RE_TMPL.format(name=re.escape(name)), stmt):
                    continue
                if re.search(rf"\b{re.escape(name)}\b", stmt):
                    line_no = _line_of(raw_src, stmt_abs_start)
                    findings.append(Finding(
                        rule_id="USE_AFTER_FREE",
                        title=f"Possible use-after-free of '{name}'",
                        cwe="CWE-416", severity="critical", file=path, line=line_no,
                        snippet=_snippet(lines, line_no),
                        description=f"'{name}' was passed to free() earlier in function "
                                    f"'{fname}' and is referenced again here with no "
                                    f"reassignment or null-guard detected in between.",
                        recommendation=f"Set {name} = NULL right after free({name}), or "
                                        f"restructure so {name} is not referenced again "
                                        f"after it's freed.",
                    ))
                    del freed[name]  # report once per free, not once per subsequent use
    return findings


def scan_file(path: str) -> list[Finding]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()
    findings = _scan_pattern_rules(path, src)
    findings += _scan_use_after_free(path, src)
    return findings


def scan_paths(paths: list[str]) -> ScanResult:
    import os
    result = ScanResult()
    exts = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp")
    targets = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for fn in files:
                    if fn.endswith(exts):
                        targets.append(os.path.join(root, fn))
        elif p.endswith(exts):
            targets.append(p)
    for t in targets:
        result.files_scanned += 1
        result.findings.extend(scan_file(t))
    return result
