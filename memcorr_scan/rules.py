"""
Rule definitions for memcorr-scan.

Each rule is intentionally simple (regex / lightweight heuristic) rather than a full
AST-based dataflow analysis — that's the honest tradeoff of a "keyless" (no license
server, no cloud API key, fully local/offline) static scanner: no external compiler
toolchain, no account, just Python + a C/C++ source tree. It will have false positives
and false negatives; that limitation is documented in the README, not hidden.
"""

import re
from dataclasses import dataclass


@dataclass
class Rule:
    id: str
    title: str
    cwe: str
    severity: str  # "critical" | "high" | "medium" | "low"
    pattern: "re.Pattern"
    description: str
    recommendation: str


DANGEROUS_FUNCTIONS = [
    ("strcpy", "CWE-120", "high",
     "strcpy() does not bound the destination buffer size.",
     "Use strncpy()/strlcpy() with an explicit size, or prefer std::string in C++."),
    ("strcat", "CWE-120", "high",
     "strcat() does not bound the destination buffer size.",
     "Use strncat()/strlcat() with an explicit size, or prefer std::string in C++."),
    ("gets", "CWE-242", "critical",
     "gets() has no way to limit input length and is inherently unsafe.",
     "Use fgets() with an explicit buffer size instead."),
    ("sprintf", "CWE-120", "high",
     "sprintf() does not bound the output buffer size.",
     "Use snprintf() with an explicit size."),
    ("vsprintf", "CWE-120", "high",
     "vsprintf() does not bound the output buffer size.",
     "Use vsnprintf() with an explicit size."),
    ("scanf", "CWE-120", "medium",
     "scanf(\"%s\", ...) with no field width can overflow the destination buffer.",
     "Specify a field width (e.g. %63s for a 64-byte buffer) or use fgets()+sscanf()."),
    ("alloca", "CWE-770", "medium",
     "alloca() allocates on the stack with no overflow check; large/attacker-controlled "
     "sizes can smash the stack.",
     "Use a heap allocation (malloc) with explicit bounds checking instead."),
]

RULES: list[Rule] = []

for fn, cwe, sev, desc, rec in DANGEROUS_FUNCTIONS:
    RULES.append(Rule(
        id=f"DANGEROUS_FN_{fn.upper()}",
        title=f"Use of unsafe function: {fn}()",
        cwe=cwe,
        severity=sev,
        pattern=re.compile(rf"\b{fn}\s*\("),
        description=desc,
        recommendation=rec,
    ))

RULES.append(Rule(
    id="FORMAT_STRING",
    title="Possible format string vulnerability",
    cwe="CWE-134",
    severity="high",
    pattern=re.compile(r"\b(printf|fprintf|syslog)\s*\(\s*([a-zA-Z_]\w*)\s*\)"),
    description="A variable is passed directly as the format argument instead of a "
                "literal format string. If the variable is attacker-influenced, this "
                "allows arbitrary memory read/write via %n and similar specifiers.",
    recommendation='Always use a literal format string, e.g. printf("%s", user_input).',
))

RULES.append(Rule(
    id="MALLOC_MULTIPLY_OVERFLOW",
    title="Unchecked multiplication in allocation size",
    cwe="CWE-190",
    severity="medium",
    pattern=re.compile(r"\b(malloc|calloc|realloc)\s*\([^)]*\*[^)]*\)"),
    description="An allocation size is computed via multiplication (e.g. "
                "malloc(count * size)) with no visible overflow check. If count or size "
                "is attacker-controlled, integer overflow can cause an undersized "
                "allocation followed by a heap buffer overflow.",
    recommendation="Use calloc(count, size) (which checks for overflow), or validate "
                    "that count * size cannot overflow before calling malloc.",
))

RULES.append(Rule(
    id="MEMCPY_VARIABLE_SIZE",
    title="memcpy/memmove with a non-constant size",
    cwe="CWE-787",
    severity="medium",
    pattern=re.compile(r"\b(memcpy|memmove)\s*\([^,]+,[^,]+,\s*[a-zA-Z_]\w*\s*\)"),
    description="The size argument is a variable rather than a compile-time constant or "
                "a sizeof() expression. Worth a manual check that it cannot exceed the "
                "destination buffer's capacity.",
    recommendation="Clamp the size to the destination buffer's known capacity before "
                    "the call, or use a bounds-checked wrapper.",
))
