# memcorr-scan

```
 source tree (*.c/*.h/*.cpp)
        |
        v
 +---------------+      +----------------------+
 |  strip pass   | ---> |  comment/string-safe |
 |  (keep line   |      |  source for matching  |
 |   numbers)    |      +----------------------+
 +---------------+                |
        |                         v
        |              +----------------------+
        |              |  pattern rules       |  dangerous fns, format
        |              |  (rules.py)          |  strings, malloc(a*b)
        |              +----------------------+
        v                         |
 +---------------+                v
 |  per-function | ---> +----------------------+
 |  brace split  |      |  use-after-free /    |
 +---------------+      |  double-free         |
                         |  heuristic           |
                         +----------------------+
                                  |
                                  v
                         +----------------------+
                         |  findings -> CLI /   |
                         |  JSON report          |
                         +----------------------+
```

## What This Is, and Why

A **local, offline, static scanner for common C/C++ memory-corruption bug classes** —
"keyless" meaning there's no license server, no API key, no cloud account to sign up for.
Point it at a directory and it reports findings immediately, which matters for anyone
scanning code they can't legally upload to a third-party SaaS (proprietary/client source,
air-gapped environments, CTF challenge sources).

It deliberately does **not** use a real C compiler frontend (no libclang/Clang AST). That's
a scope decision, not an oversight — see Limitations below. The goal of v1 is to show the
reasoning behind a static analyzer (how you turn "this call is dangerous" and "this pointer
might be used after being freed" into mechanical, repeatable checks) rather than to compete
with Coverity or CodeQL.

## Detections (v1)

| Check | CWE | What it catches |
|---|---|---|
| Unsafe function use | CWE-120/242 | `strcpy`, `strcat`, `gets`, `sprintf`, `vsprintf`, unbounded `scanf("%s", ...)`, `alloca` |
| Format string | CWE-134 | A variable passed directly as a `printf`/`fprintf`/`syslog` format argument |
| Integer overflow in allocation | CWE-190 | `malloc(count * size)` with no visible overflow guard |
| Unchecked memcpy/memmove size | CWE-787 | Variable-size copy with no visible bounds clamp |
| Use-after-free | CWE-416 | A pointer referenced after `free()` in the same function, with no reassignment/guard in between |
| Double free | CWE-415 | A pointer passed to `free()` twice with no reassignment in between |

## Quickstart

```bash
python3 -m memcorr_scan.cli test_samples/vulnerable.c
python3 -m memcorr_scan.cli ./my-project/src --min-severity high --json report.json
python3 -m memcorr_scan.cli ./my-project/src --fail-on critical   # CI gate: exit 1 on any critical finding
```

Sample output against `test_samples/vulnerable.c` (a file written specifically to exercise
every rule, including one *safe* function that should produce zero findings):

```
memcorr-scan: 1 file(s) scanned, 5 finding(s)

  critical: 1  high: 3  medium: 1  low: 0

[CRITICAL] Possible use-after-free of 'ptr' (CWE-416)
  test_samples/vulnerable.c:20
    printf("%s\n", ptr);
  -> 'ptr' was passed to free() earlier in function 'uaf_example' ...
```

 Validation Against a Known-Vulnerable Codebase

Testing against a hand-written sample file proves the rules fire — it doesn't prove the
tool is useful against real code. So I ran it against
[Damn Vulnerable C Program](https://github.com/hardik05/Damn_Vulnerable_C_Program), a
public C codebase built specifically to contain realistic memory-corruption bugs for
practicing tools like fuzzers and static analyzers.memcorr-scan: 16 file(s) scanned, 10 finding(s)

critical: 5 high: 5 medium: 0 low: 0

[CRITICAL] Possible use-after-free of ‘buff1’ (CWE-416)
dvcp.c:67
buff1[0]='a';
-> ‘buff1’ was passed to free() earlier in function ‘ProcessImage’ and is referenced
again here with no reassignment or null-guard detected in between.

[HIGH] Possible double free of ‘buff1’ (CWE-415)
dvcp.c:62
free(buff1);
-> ‘buff1’ appears to be passed to free() twice in function ‘ProcessImage’ with no
reassignment in between.


It correctly identified a genuine **double-free followed by a use-after-free** inside the
codebase's `ProcessImage` function — the same function, copy-pasted across 5 files in the
repo (`dvcp.c`, `imgRead.c`, and 3 fuzzing-harness variants under `libAFL/`), which is why
the same two-bug pattern surfaces 10 times rather than being 10 distinct bugs. A
double-free-then-use-after-free chain in image-processing code is exactly the bug class
responsible for real-world CVEs in image parsing libraries (a malicious input file
triggers the bug; if an attacker controls what gets written into the freed memory, it can
lead to code execution) — so this wasn't just a clean pattern match, it was the tool
correctly flagging a security-relevant bug class in code built to resemble a real
vulnerable target.## A Real Problem and How I Solved It

**The problem:** a pure-regex approach to "dangerous function" detection is easy, but a
regex has no concept of *control flow* — it can't tell the difference between
`free(ptr); ptr = NULL; use(ptr);` (safe) and `free(ptr); use(ptr);` (a real
use-after-free). Flagging every post-`free()` mention of a pointer name anywhere in the
file would drown real findings in false positives from completely unrelated functions
that happen to reuse a common variable name like `ptr` or `buf`.

**How I solved it:** rather than reach for a full AST library, I scoped the heuristic to
*within a single function body*, found via brace-depth matching from each function
signature. Inside that scope, I walk statements in order, track which pointers have been
freed, and clear that tracking the moment I see a reassignment (`ptr = ...`) or a null
guard (`if (ptr)` / `while (ptr)`). Anything still tracked as "freed" when the name
reappears gets flagged — once per `free()`, not once per subsequent mention, to avoid
spamming the same bug three times in a ten-line function.

**What it still gets wrong:** this scoping to "one function, one variable name" means it
will miss a use-after-free where the pointer is passed to another function before the
dangling use (true negative), and it can still misfire if a variable is freed, goes out of
scope in a nested block, and an unrelated variable with the same name is declared later in
the same function (false positive) — a real AST with proper scope tracking wouldn't make
that mistake. That tradeoff is explicit, not hidden.

## Limitations (read before you trust a finding)

- No real parser — a regex/brace-matching approach will misfire on heavily macro'd code,
  multi-line statements with embedded commas inside casts, and anything relying on
  non-obvious preprocessor expansion.
- No interprocedural analysis — a pointer freed in one function and misused in a function
  it was passed into will **not** be caught.
- No data-flow for the format-string and malloc-overflow rules beyond "is this a literal
  or a variable" — a variable that is provably a compile-time constant will still be
  flagged.
- Every finding here is a **lead to manually verify**, not a confirmed bug.

## What I'd Improve

- Swap the brace-matching function extractor for `pycparser` or `libclang` to get a real
  AST and proper scope/interprocedural tracking — the single biggest accuracy jump
  available.
- Add a taint-tracking pass for the format-string rule (flag only when the variable
  traces back to an unsanitized `argv`/`read`/`recv`/network input, not any variable).
- Add a suppression mechanism (`// memcorr-scan: ignore[DOUBLE_FREE]`) for confirmed false
  positives, so the tool is usable as a CI gate without constant noise.
- Benchmark against a known-vulnerable corpus (e.g. the Juliet Test Suite's CWE-416/CWE-415
  cases) to get a real precision/recall number instead of eyeballing one hand-written
  sample file.
- Add a minimal taint source/sink table for common network-facing input functions
  (`recv`, `read`, `getenv`) to prioritize findings that are actually reachable from
  untrusted input.
